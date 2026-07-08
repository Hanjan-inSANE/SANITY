# sanity_scenario_manager/allocator.py
from sanity_common.contracts import BudgetGrant, AttackPath, AttackContext, CompromiseContext
from sanity_common.toolset import Toolset
from sanity_common.state import State
from sanity_common.config import SanityConfig
from sanity_common.aio import run_sync as _await            # MCP 동기 브리지(§00-2.1)
from sanity_llm import issue_key                            # 6. Gateway 정본(gateway_log), §00-7.3

class Allocator:
    def __init__(self, tree_id, cfg: SanityConfig, bus, state: State):
        self.tree_id=tree_id; self.cfg=cfg; self.bus=bus; self.state=state
        self.ts = Toolset(cfg.toolset_root)               # stdio Toolset(§00-8.5)
        # LITELLM_API_BASE(=cfg.gateway_url)·SANITY_LITELLM_MASTER_KEY는 env(secret)로 주입(§00-7.3)

    def _issue_key(self, grant: BudgetGrant) -> str:         # DM-11 → 가상키(§00-7.3)
        return issue_key(key_alias=grant.scope_id, token_budget=grant.token_budget,
                         token_price_per_1k=self.cfg.token_price_per_1k,
                         models=self.cfg.gateway_models,   # 기본+폴백 티어(폴백 auth-reject 방지)
                         rpm_limit=grant.rpm_limit, tpm_limit=grant.tpm_limit,
                         base_url=self.cfg.gateway_url,
                         metadata={"scope_id": grant.scope_id, "wall_clock_s": grant.wall_clock_s})

    # --- 2.2.1+2.2.2: Attacker 스폰 + 예산 + 핸드오프 (FR-SM-03/04) ---
    def spawn_attacker(self, node: dict, path: AttackPath) -> str:   # 동기(§00-2.1)
        tnode_id = node["tnode_id"]; scope_id = f"att:{self.tree_id}:{tnode_id}"
        grant = self._budget(scope_id, path)                 # FR-SM-04
        grant.virtual_key = self._issue_key(grant)           # → LiteLLM /key/generate (§00-7.3); 키를 grant에 기입
        ctx = self._compromise_ctx(path)                     # DM-4 선행 침해 상태
        # Allocator가 workspace 소유(FR-SR-CONCUR-04). 실제 create_workspace는 target 개념 없음(§00-8.2).
        ws = _await(self.ts.diag("create_workspace", {"workspace_id": scope_id}))
        workspace_root = ws["workspace_root"]                # 공유 볼륨 경로 — 이후 모든 도구 호출의 첫 인자
        payload = {"node": node, "compromise_ctx": ctx.model_dump(),
                   "budget": grant.model_dump(), "workspace_root": workspace_root,
                   "mav_endpoint": "target-sitl-a:5760",     # 로직 클래스 run_tool용 SITL 엔드포인트(§10)
                   "trace_id": self._trace(tnode_id), "scope_id": scope_id,
                   "tree_id": self.tree_id, "path_id": path.path_id,
                   "gateway_model": self.cfg.gateway_model, "gateway_url": self.cfg.gateway_url,
                   "toolset_root": self.cfg.toolset_root, "max_retry": self.cfg.max_retry}
        self.bus.publish(f"sanity:dispatch:attacker:{scope_id}", payload)
        self._spawn_container("attacker", scope_id, payload) # 도커/K8s Job (동적 스폰)
        self._set_pending(scope_id, "attacker")
        self._arm_wallclock(scope_id, grant.wall_clock_s)    # Allocator가 wall-clock 강제(§00-7.2)
        return scope_id

    # --- 2.3.3 요청 시: Defender 스폰 (FR-SM-07, FR-SR-CONCUR-03/04) ---
    def spawn_defender(self, attack_ctx: AttackContext) -> str:   # 동기(§00-2.1)
        tnode_id = attack_ctx.pov.tnode_id; scope_id = f"def:{self.tree_id}:{tnode_id}"
        grant = self._budget(scope_id, None)
        grant.virtual_key = self._issue_key(grant)           # 키를 grant에 기입(에이전트가 budget.virtual_key로 사용)
        # crash 클래스: Defender는 Attacker의 workspace를 재사용(baseline build 존재 + crash input).
        # orig/clone은 별도 인스턴스가 아니라 같은 workspace의 build 변형(§00-10). 새 workspace 생성 안 함.
        workspace_root = attack_ctx.target_ref               # = Attacker가 쓴 workspace_root
        self.state.r.set(f"st:pov:{attack_ctx.pov.pov_id}", attack_ctx.pov.model_dump_json())
        payload = {"attack_context": attack_ctx.model_dump(), "budget": grant.model_dump(),
                   "workspace_root": workspace_root,
                   "mav_endpoint": "target-sitl-b:5760",     # 로직 클래스 방어검증용 2번째 SITL(§10)
                   "trace_id": self._trace(tnode_id), "scope_id": scope_id,
                   "tree_id": self.tree_id, "gateway_model": self.cfg.gateway_model,
                   "gateway_url": self.cfg.gateway_url, "toolset_root": self.cfg.toolset_root,
                   "max_retry": self.cfg.max_retry}
        self.bus.publish(f"sanity:dispatch:defender:{scope_id}", payload)
        self._spawn_container("defender", scope_id, payload)
        self._set_pending(scope_id, "defender")
        self._arm_wallclock(scope_id, grant.wall_clock_s)
        return scope_id

    def _budget(self, scope_id: str, path: AttackPath | None) -> BudgetGrant:
        """예선 기본: 총예산 / max(1, 잔여 노드수) 균등. config 가중 오버라이드."""
        remaining = self._remaining_node_count()             # 미착수+진행 노드 수
        share = self.cfg.total_token_budget // max(1, remaining)
        return BudgetGrant(scope_id=scope_id, virtual_key="",  # issue_key가 채움
                           token_budget=share, rpm_limit=self.cfg.default_rpm,
                           tpm_limit=self.cfg.default_tpm,
                           wall_clock_s=self._wallclock_share(), expires_at=None)

    def _arm_wallclock(self, scope_id: str, seconds: int | None) -> None:
        """Gateway가 아니라 Allocator가 per-agent 시한 강제. 만료 시 FAIL status 자가 방출.
        동기 모델이므로 threading.Timer로 무장(SM 스레드를 막지 않음)."""
        if not seconds: return
        import threading
        t = threading.Timer(seconds, self._force_fail, args=(scope_id,)); t.daemon = True; t.start()

    def _trace(self, tnode_id: str) -> str:                       # SR-OBSV-01 trace 규약(§00-9)
        return f"{self.tree_id}::{tnode_id}"
    def _remaining_node_count(self) -> int:                       # FR-SM-04 분모
        """현재 트리에서 아직 SUCCESS가 아닌 노드 수(최소 1). State successes로 계산."""
        succ = self.state.successes(self.tree_id)
        tree = self.state.get_tree(self.tree_id); total = [0]
        def walk(n):
            total[0] += 1
            for c in n.get("children") or []: walk(c)
        walk(tree); return max(1, total[0] - len(succ))
    def _wallclock_share(self) -> int:                            # per-agent 시한(config)
        return self.cfg.default_wall_clock_s
    def _compromise_ctx(self, path) -> CompromiseContext:         # FR-SM-03 핸드오프 DM-4
        return self.state.get_ctx(path.path_id) or CompromiseContext(path_id=path.path_id, compromised=[])
    def _set_pending(self, scope_id: str, kind: str) -> None:     # DM-5 초기 상태
        from sanity_common.contracts import InstanceState
        self.state.set_state(InstanceState(scope_id=scope_id, kind=kind, state="PENDING", retries=0))
    def _spawn_container(self, role: str, scope_id: str, payload: dict) -> None:
        """에이전트 인스턴스를 동적 스폰(오케스트레이션 권한은 2.3 귀속; 물리 스폰만 여기서).
        예선=docker SDK, 본선=K8s Job. 이미지에 프로바이더 키 미주입(SR-STACK-02);
        env로 SANITY_SCOPE_ID·SANITY_LOG_DIR·TOOLSET_ROOT만, 나머지(gateway_url/가상키/workspace_root)는 dispatch로 전송됨.
        role ∈ {"attacker","defender"} → 이미지 sanity_attacker / sanity_defender.
        MUST: 로그 공유 볼륨(sanity-logs)을 마운트해야 동적 컨테이너 로그가 유실되지 않는다(FR-IF-7)."""
        import docker
        docker.from_env().containers.run(
            image=f"sanity_{role}:latest", detach=True, network="control",
            environment={"SANITY_SCOPE_ID": scope_id,
                         "SANITY_LOG_DIR": "/logs",                 # LogWriter 출력 위치(§00-9)
                         "TOOLSET_ROOT": self.cfg.toolset_root,     # stdio Toolset PYTHONPATH(§00-8.5)
                         "REDIS_URL_BUS": self.cfg.redis_url_bus,
                         "REDIS_URL_STATE": self.cfg.redis_url_state},
            volumes={"sanity-logs": {"bind": "/logs", "mode": "rw"},        # 로그 공유 볼륨
                     "toolset-ws": {"bind": "/workspaces", "mode": "rw"}},  # Toolset workspace 공유(§00-8.1)
            name=f"{role}-{scope_id.replace(':','_')}", remove=True)
    def _force_fail(self, scope_id: str) -> None:                 # wall-clock 만료 시(FR-SR-BUDGET-01)
        self.bus.publish(f"sanity:status:{self.tree_id}",
            {"ts":0,"trace_id":scope_id,"component":"2.2","scope_id":scope_id,
             "event_type":"status","state":"FAIL"})
