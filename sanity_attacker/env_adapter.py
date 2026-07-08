# sanity_attacker/env_adapter.py
import json
from sanity_common.aio import run_sync as _await          # MCP 코루틴 동기 실행(§00-2.1)
def _json(x): return json.dumps(x, ensure_ascii=False)     # 예시에서 쓰는 자명 헬퍼
from sanity_common.contracts import CompromiseContext

def parse_context(s: dict, log) -> dict:
    """노드(DM-2)와 CompromiseContext(DM-4)를 파싱해 공격 표면·선행 foothold 식별."""
    node = s["node"]
    surface = {
        "protocols": _channels_of(node),                 # dfd_channel / config ch.tech
        "interfaces": [],                                 # config ch.interface
        "entrypoints": [node.get("dfd_component")],       # 진입 컴포넌트
        "footholds": CompromiseContext(**s["compromise_ctx"]).compromised,  # 선행 침해
        "harness": node.get("build_ref") or node.get("surface_kind"),  # whitebox fuzz용(있으면; 없으면 None→blackbox)
        "summary": node.get("summary",""), "attack_context": node.get("attack_context",""),
        "evidence": [e.get("id") for e in node.get("evidence",[])],
    }
    log.event(trace_id=s["trace_id"], component="3.1", event_type="status", state="RUNNING",
              scope_id=s["scope_id"])
    return {"surface": surface}

def select_tools(s: dict, gw, ts, log) -> dict:
    # ⚠ priority=None (기본 P0는 로직/네트워크 P2 도구를 숨김, §00-8.3). 전 도구를 봐야 클래스 판정 가능.
    inv = _await(ts.list_tools(kind=None, priority=None))                 # ToolDescriptor[]
    from .prompts import TOOL_SELECT_SYSTEM
    from sanity_llm import wrap_untrusted                                 # §00-7.4
    user = wrap_untrusted("node", _json({"surface": s["surface"], "inventory":
              [{"tool_id":t["tool_id"],"kind":t["kind"],"display_name":t["display_name"]} for t in inv]}))
    # LLM은 신뢰불가 노드 데이터를 '데이터로만' 받는다(SR-SEC-01). complete_json=엄격JSON+1회 자가수리.
    sel = gw.complete_json(s["gateway_model"], user=user, system=TOOL_SELECT_SYSTEM,
                           trace_id=s["trace_id"], scope_id=s["scope_id"])
    # sel = {"tool_ids":[...], "mode":"whitebox|blackbox", "rationale":str}
    from sanity_common.contracts import attack_class_of_tools
    tools = [t for t in inv if t["tool_id"] in sel.get("tool_ids", [])]
    feasible = len(tools) > 0
    klass = attack_class_of_tools([t["kind"] for t in tools])  # FR-AT-05: kind → crash|logic (§00-3.1 정본)
    if not feasible:
        log.event(trace_id=s["trace_id"], component="3.1", event_type="status",
                  state="FAIL", scope_id=s["scope_id"])        # (fail 노드가 2.3에 최종 방출)
    return {"selected_tools": tools, "attack_class": klass, "feasible": feasible,
            "fuzz_mode": sel.get("mode","blackbox")}

def prepare_toolset(s: dict, log) -> dict:
    """Allocator가 발급한 workspace(dispatch의 workspace_root)를 재사용한다(create_workspace 호출 금지).
    실제 준비는 실행 시점(build/start_fuzz/run_tool)에 Toolset이 담당."""
    return {"workspace_root": s["workspace_root"]}

# --- 로컬 순수 헬퍼(정의 고정, 재발명 아님; §7 로컬 헬퍼) ---
def _channels_of(node: dict) -> list:
    """노드의 통신 채널(dfd_channel)을 리스트로. 없으면 빈 리스트."""
    ch = node.get("dfd_channel")
    return [ch] if ch else []
