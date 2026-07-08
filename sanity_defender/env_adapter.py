# sanity_defender/env_adapter.py
import json
from sanity_common.aio import run_sync as _await          # MCP 코루틴 동기 실행(§00-2.1)
def _json(x): return json.dumps(x, ensure_ascii=False)
from sanity_common.contracts import AttackContext

def parse_ctx(s: dict, log) -> dict:
    """2.3.3이 dispatch 시 주입한 AttackContext를 파싱해 exploit 유형·영향 노드(tnode_id)·PoV 식별.
    Attacker로부터 직접 수신하지 않는다(FR-SR-CONCUR-03). attack_class는 여기서 저장하지 않고
    select_defense에서 PoV.tool의 kind로 파생한다(§00-3.1) — DM-6에 없는 필드 미사용."""
    actx = AttackContext(**s["attack_context"])
    log.event(trace_id=s["trace_id"], component="4.1", event_type="status",
              state="RUNNING", scope_id=s["scope_id"])
    # workspace_root는 dispatch(s["workspace_root"]) 정본. actx.target_ref도 동일 workspace(§00-10).
    return {"_pov": actx.pov.model_dump()}

def select_defense(s: dict, gw, ts, log) -> dict:
    from sanity_common.contracts import attack_class_of_kind
    inv = _await(ts.list_tools(kind=None, priority=None))         # priority=None: P2 로직 도구 포함(§00-8.3)
    # attack_class 파생: PoV.tool의 kind를 레지스트리에서 조회(§00-3.1). Attacker와 동일 함수 → 항상 일치.
    tool_kind = next((t["kind"] for t in inv if t["tool_id"] == s["_pov"]["tool"]), "")
    attack_class = attack_class_of_kind(tool_kind)               # "crash" | "logic"
    if attack_class == "crash":
        kind = "source_patch"; want = {"patcher","builder","sanitizer","test_runner"}
    else:
        kind = "config_harden"; want = {"config_hardener","ids_rule_validator","network_scanner"}
    tools = [t for t in inv if t["kind"] in want]
    return {"attack_class": attack_class, "defense_kind": kind, "selected_tools": tools}

def prepare_toolset(s: dict, log) -> dict:
    """⚠ Defender는 workspace를 생성하지 않는다(FR-SR-CONCUR-04). Attacker가 쓴 workspace_root
    (dispatch로 전달)를 그대로 재사용한다(crash: baseline build + crash input이 이미 있음).
    검사(§00-13): sanity_defender에 create_workspace 호출 0건."""
    return {"workspace_root": s["workspace_root"]}
