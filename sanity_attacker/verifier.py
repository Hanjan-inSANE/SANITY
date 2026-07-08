# sanity_attacker/verifier.py
import json
from sanity_common.aio import run_sync as _await          # MCP 코루틴 동기 실행(§00-2.1)
def _json(x): return json.dumps(x, ensure_ascii=False)     # 예시에서 쓰는 자명 헬퍼

def judge(s: dict, gw, log) -> dict:
    sig = s["signals"]                                # 5.2에서 수집됨(실제 Toolset 결과)
    if s["attack_class"] == "crash":
        # crash oracle = reproduce_pov.reproduced(비정상 종료/시그널/timeout) ∨ sanitizer finding (§00-8.2)
        ok = bool(sig.get("reproduced") or sig.get("sanitizer_finding"))
    else:
        # ⚠ logic oracle 부재(§00-8.4): run_tool stdout를 LLM으로 판정(외부 관측 취지).
        from .prompts import LOGIC_JUDGE_SYSTEM
        from sanity_llm import wrap_untrusted
        verdict = gw.complete_json(s["gateway_model"], system=LOGIC_JUDGE_SYSTEM,
                    user=wrap_untrusted("tool_stdout", _json({"stdout_ref": sig.get("stdout_ref"),
                        "artifact_refs": sig.get("artifact_refs")})),
                    trace_id=s["trace_id"], scope_id=s["scope_id"])
        ok = bool(verdict.get("state_change") or verdict.get("auth_bypassed"))   # {state_change,auth_bypassed,...}
        s["signals"].update(verdict)                  # 판정 결과를 신호에 병합(record에서 sig 산출용)
    log.event(trace_id=s["trace_id"], component="3.3", event_type="status",
              state="RUNNING", scope_id=s["scope_id"])
    return {"success": ok}

import uuid
from sanity_common.contracts import PoV, AttackContext, CompromiseContext, EventEnvelope
from sanity_common.state import exploit_signature

def record_and_emit(s: dict, state, bus, log) -> dict:
    sg = s["signals"]
    sig = exploit_signature(
        s["attack_class"],
        stacktrace=sg.get("stacktrace",""), sanitizer=str(sg.get("sanitizer_finding","")),
        effect=_effect(s), attack_seq=sg.get("sequence"), affected_params=sg.get("params"))
    # ⚠ Defender가 PoV.tool의 kind로 attack_class를 재파생하므로(§00-3.1), 기록할 tool은 반드시
    #   '클래스를 결정한 도구'여야 한다(kind가 s["attack_class"]와 일치하는 첫 도구).
    from sanity_common.contracts import attack_class_of_kind
    primary = next((t for t in s["selected_tools"]
                    if attack_class_of_kind(t["kind"]) == s["attack_class"]), s["selected_tools"][0])
    pov = PoV(pov_id="pov_"+uuid.uuid4().hex[:12], tnode_id=s["node"]["tnode_id"],
              tool=primary["tool_id"], input_blob_ref=sg.get("input_blob_ref") or s["seed_ref"],
              pre_snapshot_ref="",                    # 실제 Toolset엔 snapshot 없음 → replay로 대체(§00-8.4)
              exploit_signature=sig, effect=_effect(s),
              replay_command=None, crash_report_ref=sg.get("crash_report_ref"))
    # PoV에 attack_class를 저장하지 않는다(DM-6 필드 아님). s["attack_class"]는 그래프 상태일 뿐.
    # target_ref = workspace_root: crash 클래스에서 Defender가 같은 workspace를 재사용(§00-10).
    actx = AttackContext(pov=pov, compromise_ctx=CompromiseContext(**s["compromise_ctx"]),
                         target_ref=s["workspace_root"])
    ref = f"actx:{pov.pov_id}"
    state.r.set(f"st:{ref}", actx.model_dump_json())          # 2.3이 dereference (payload_ref)
    state.r.set(f"st:pov:{pov.pov_id}", pov.model_dump_json())
    log.event(trace_id=s["trace_id"], component="3.3", event_type="artifact",
              scope_id=s["scope_id"], payload_ref=f"st:pov:{pov.pov_id}")   # PoV 필수 기록(FR-OBSV-01)
    # SUCCESS status + AttackContext ref → 2.3 (Attacker→Defender 직접 엣지 없음)
    bus.publish(f"sanity:status:{s['tree_id']}",
                EventEnvelope(ts=0, trace_id=s["trace_id"], component="3",
                              scope_id=s["scope_id"], event_type="status",
                              state="SUCCESS", payload_ref=f"st:{ref}").model_dump())
    return {"success": True, "pov": pov.model_dump()}

def emit_fail(s: dict, bus, log) -> dict:
    """실행불가(3.1) 또는 재시도/예산 소진(FR-SR-BUDGET-02) → FAIL status를 2.3으로."""
    bus.publish(f"sanity:status:{s['tree_id']}",
                EventEnvelope(ts=0, trace_id=s["trace_id"], component="3",
                              scope_id=s["scope_id"], event_type="status", state="FAIL").model_dump())
    return {"success": False}

# --- 로컬 순수 헬퍼(정의 고정, 재발명 아님; §7 로컬 헬퍼) ---
def _effect(s: dict) -> str:
    """관측 신호 → effect 라벨(crash|dos|unauthorized|spoof). effect는 클래스와 독립(DM-6 비고)."""
    sg = s.get("signals", {})
    if s.get("attack_class") == "crash":
        if sg.get("unresponsive") and not sg.get("reproduced"):
            return "dos"
        return "crash"
    # logic
    if sg.get("auth_bypassed"):
        return "unauthorized"
    if sg.get("state_change"):
        return "spoof"
    return "unauthorized"
