# sanity_scenario_manager/task_manager.py
import json
from dataclasses import dataclass
from sanity_common.contracts import EventEnvelope, InstanceState, AttackContext, Foothold
from sanity_common.state import State   # §00-6.3

@dataclass
class Action:
    kind: str                     # ATTACK_NEXT|DISPATCH_DEFENDER|PATH_ABORT|PATH_ALT|COLLECT|ROOT_DONE|NOOP
    attack_ctx: AttackContext | None = None
    artifact: dict | None = None
    root_done: bool = False       # DISPATCH_DEFENDER와 동시에 root 달성 시 True → finalize (m2/B3)

class TaskManager:
    def __init__(self, tree_id, tree, cfg, bus, state: State, allocator, path_extractor):
        self.tree_id=tree_id; self.tree=tree; self.cfg=cfg; self.bus=bus
        self.state=state; self.alloc=allocator; self.pe=path_extractor

    def on_status(self, obj: dict) -> Action:                                    # 동기(§00-2.1)
        ev = EventEnvelope(**obj) if not isinstance(obj, EventEnvelope) else obj  # 2.3.1 정규화
        scope_id = ev.scope_id
        st = self.state.get_state(scope_id) or InstanceState(scope_id=scope_id, kind=self._kind(scope_id), state="PENDING")
        st.state = ev.state or st.state                                          # 2.3.2 전이
        self.state.set_state(st)                                                 # FR-SM-06
        if ev.state == "SUCCESS":
            if scope_id.startswith("att:"): return self._on_attack_success(ev)
            if scope_id.startswith("def:"): return self._on_defense_success(ev)
        if ev.state == "FAIL":
            if scope_id.startswith("def:"): return Action("DEF_FAILED")   # 방어 실패: 경로제어 안 함(공격경로 무관)
            return self._on_fail(ev, scope_id)                            # attacker 실패 → 경로 제어(FR-SM-10)
        return Action("NOOP")

    def _on_attack_success(self, ev: EventEnvelope) -> Action:    # 동기(§00-2.1)
        actx = AttackContext(**self._deref(ev.payload_ref))       # DM-6 (2.3이 dereference)
        pov = actx.pov; tnode_id = pov.tnode_id
        # (1) dedup 게이트가 디스패치보다 선행 (FR-SM-09) — 중복이면 디스패치 생략
        is_new = self.state.dedup_check_and_add(self.tree_id, tnode_id, pov.exploit_signature)  # INV-3
        # (2) CompromiseContext에 성공 foothold 추가 (DM-4). access/privilege는 effect→foothold 사상.
        self.state.add_foothold(actx.compromise_ctx.path_id,
                                Foothold(tnode_id=tnode_id, access=_access_of(pov.effect),
                                         privilege=_priv_of(pov), artifacts={"input": pov.input_blob_ref}))
        # (3) leaf 성공을 트리 상방으로 전파 → gate 충족·root 달성 계산 (FR-SM-08)
        self.state.mark_success(self.tree_id, tnode_id)
        root_done = self._root_satisfied()                        # AND=자식 전부, OR=자식 1개
        # (4) unique면 Defender 디스패치(2.3.3 단독) — 최종 침해 노드도 방어 대상(FR-SR-CONCUR-02).
        #     root_done을 함께 실어 manager가 디스패치 후 finalize (m2). B3: root 미달성이면 공격 계속.
        if is_new:
            return Action("DISPATCH_DEFENDER", attack_ctx=actx, root_done=root_done)
        return Action("ROOT_DONE") if root_done else Action("ATTACK_NEXT")

    def _root_satisfied(self) -> bool:
        succ = self.state.successes(self.tree_id)                 # 성공 tnode_id 집합
        def ok(n: dict) -> bool:
            kids = n.get("children") or []
            if not kids: return n["tnode_id"] in succ             # leaf
            gate = (n.get("logic") or "AND").upper()
            res = [ok(c) for c in kids]
            node_ok = all(res) if gate=="AND" else any(res)
            return node_ok or (n["tnode_id"] in succ)             # DAG memoize 허용(§00-4)
        return ok(self.tree)

    def _on_fail(self, ev: EventEnvelope, scope_id: str) -> Action:
        """재시도 상한/예산 소진, 또는 Attacker 3.1의 실행불가(FAIL) 통보.
        현재 노드의 gate가 AND(필수)면 경로 abort, OR면 대안 경로 전환(2.1 회귀)."""
        gate = self._current_gate(scope_id)
        if gate == "AND": return Action("PATH_ABORT")             # 필수 노드 실패 → 경로 포기
        return Action("PATH_ALT")                                 # OR → 대안 경로

    def _on_defense_success(self, ev: EventEnvelope) -> Action:
        patch_ref = ev.payload_ref                                 # DM-7 Patch ref
        return Action("COLLECT", artifact={"kind":"patch","ref":patch_ref, "scope_id": ev.scope_id})

    def _deref(self, payload_ref: str) -> dict:                   # §00-6.1 payload_ref=완전한 State 키
        return json.loads(self.state.r.get(payload_ref))          # 접두사 재부착 금지
    def _kind(self, scope_id: str) -> str:                        # DM-5 kind 판정
        return "attacker" if scope_id.startswith("att:") else "defender" if scope_id.startswith("def:") else "scenario"
    def _current_gate(self, scope_id: str) -> str:                # FR-SM-10 경로제어용 gate
        """실패한 노드의 gate(AND/OR/LEAF)를 현재 경로 gate_seq에서 조회.
        scope_id=att:{tree_id}:{tnode_id} → 현재 경로의 해당 index gate."""
        tnode_id = scope_id.split(":")[-1]
        ap = self.pe.current_path()
        for i, t in enumerate(ap.node_seq):
            if t == tnode_id: return ap.gate_seq[i]
        return "AND"                                              # 미발견 시 보수적(필수로 취급)

# --- effect(DM-6) → Foothold(DM-4) 사상 (best-effort, 관측 라벨→침해 서술) ---
def _access_of(effect: str) -> str:
    return {"crash":"rce","dos":"dos","unauthorized":"auth-bypass","spoof":"spoof-session"}.get(effect, effect)
def _priv_of(pov) -> str:
    # PoV는 privilege를 담지 않음 → effect 기반 보수적 추정. artifacts에 세션정보 있으면 상위.
    return "operator" if pov.effect in ("unauthorized","spoof") else "user"
