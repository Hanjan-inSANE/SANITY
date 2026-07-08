# sanity_defender/verifier.py
import os
import json
from sanity_common.aio import run_sync as _await          # MCP 코루틴 동기 실행(§00-2.1)
def _json(x): return json.dumps(x, ensure_ascii=False)

def verify(s: dict, ts, log) -> dict:
    ws = s["workspace_root"]; tid = s["trace_id"]; pov = s["_pov"]; inp = pov["input_blob_ref"]
    if s["attack_class"] == "crash":
        # ⚠ 관측형 도구는 sig(ok, diagnostics) — 크래시=ok False라 diag는 예외(§00-8.5).
        bl = _await(ts.diag("build", {"workspace_root": ws, "build_dir":"build", "sanitizer":"asan", "trace_id": tid}))
        bl_cmd = _target_cmd_of(ws, bl, build_dir="build")           # baseline 바이너리
        _o1, d1 = _await(ts.sig("reproduce_pov", {"workspace_root": ws, "target_cmd": bl_cmd, "input_blob_ref": inp, "trace_id": tid}))
        g_base = bool(d1.get("reproduced"))                          # baseline은 재현되어야 PoV 유효
        _o2, d2 = _await(ts.sig("reproduce_pov", {"workspace_root": ws, "target_cmd": s["target_cmd"], "input_blob_ref": inp, "trace_id": tid}))
        g_patch_blocked = not bool(d2.get("reproduced"))             # patched는 막혀야(reproduced=False)
        g_build = s.get("patched_build_success", False)
        g_reg, _dr = _await(ts.sig("run_tests", {"workspace_root": ws, "test_runner": _test_runner_of(ws), "build_dir":"build_patched", "trace_id": tid}))  # envelope ok=통과(정본)
        _o3, d3 = _await(ts.sig("run_sanitizer", {"workspace_root": ws, "sanitizer":"asan", "target_cmd": s["target_cmd"], "trace_id": tid}))
        g_san = not bool(d3.get("finding_observed"))                 # 정본 키: finding_observed
        # 증거 번들
        ev = _await(ts.diag("export_evidence", {"workspace_root": ws, "trace_id": tid, "verdict":"defense_verified",
                    "pov_ref": pov.get("pov_id"), "patch_ref": s.get("patch_ref")}))
        g_evd = bool(ev.get("bundle_ref"))
        # compare_baseline: 6 게이트를 넘겨 순수 AND 판정(§00-8.2)
        _okc, cmp = _await(ts.sig("compare_baseline", {"workspace_root": ws,
                     "baseline_pov_reproduces": g_base, "patched_pov_blocked": g_patch_blocked,
                     "patched_build_success": g_build, "regression_tests_pass": g_reg,
                     "no_new_sanitizer_finding_on_replay": g_san, "evidence_bundle_complete": g_evd}))
        neutralized = g_base and g_patch_blocked and g_san
        no_reg = g_build and g_reg
        success = cmp.get("verdict") == "defense_verified"
        return {"neutralized": neutralized, "no_regression": no_reg, "success": success, "bundle_ref": ev.get("bundle_ref")}
    else:   # logic(§00-8.4 공백): 하드닝 후 공격 시퀀스 재현 → LLM 판정(무력화) + 정상 미션 stdout 판정(무회귀)
        rep = _await(ts.diag("run_tool", {"workspace_root": ws, "tool_id": pov["tool"],
                     "params": {"mav_endpoint": s["mav_endpoint"], "seed_ref": inp}, "trace_id": tid}))
        neutralized = _llm_logic_blocked(s, rep)          # stdout 파싱 LLM 판정(공격 거부/텔레메트리 정상)
        mission = _await(ts.diag("run_tool", {"workspace_root": ws, "tool_id":"mav_heartbeat",
                     "params": {"mav_endpoint": s["mav_endpoint"]}, "trace_id": tid}))
        no_reg = _llm_mission_ok(s, mission)
        success = neutralized and no_reg
        return {"neutralized": neutralized, "no_regression": no_reg, "success": success}

import uuid
from sanity_common.contracts import Patch, EventEnvelope

def emit_patch(s: dict, state, bus, log) -> dict:
    pov = s["_pov"]
    patch = Patch(patch_id="patch_"+uuid.uuid4().hex[:12], pov_id=pov["pov_id"],
                  target_files=s.get("_target_files", []), diff=s["diff"],
                  applies_to=s["workspace_root"])
    state.r.set(f"st:patch:{patch.patch_id}", patch.model_dump_json())
    log.event(trace_id=s["trace_id"], component="4.3", event_type="artifact",
              scope_id=s["scope_id"], payload_ref=f"st:patch:{patch.patch_id}")  # Patch 필수 기록
    bus.publish(f"sanity:status:{s['tree_id']}",
                EventEnvelope(ts=0, trace_id=s["trace_id"], component="4",
                              scope_id=s["scope_id"], event_type="status",
                              state="SUCCESS", payload_ref=f"st:patch:{patch.patch_id}").model_dump())
    return {"success": True, "patch": patch.model_dump()}

def emit_fail(s: dict, bus, log) -> dict:
    bus.publish(f"sanity:status:{s['tree_id']}",
                EventEnvelope(ts=0, trace_id=s["trace_id"], component="4",
                              scope_id=s["scope_id"], event_type="status", state="FAIL").model_dump())
    return {"success": False}

# --- 로컬 순수/보조 헬퍼(정의 고정, 재발명 아님; §7 로컬 헬퍼) ---
def _target_cmd_of(ws: str, build_diag: dict, build_dir: str = "build") -> list:
    ref = (build_diag or {}).get("build_artifact_ref") or ""
    binname = os.path.basename(ref) if ref else ""
    if ref and ("/" in ref or "\\" in ref) and not ref.startswith(("artifact://",)):
        return [ref]
    if binname and not binname.startswith("artifact"):
        return [f"{ws}/{build_dir}/{binname}"]
    return [f"{ws}/{build_dir}/a.out"]

def _test_runner_of(ws: str) -> str:
    """detect_target 의 target_profile.build_system → ctest/pytest/junit 매핑.
    crash 챌린지는 C/C++(cmake) 중심이므로 기본 ctest."""
    return "ctest"

def _gw_for(s: dict):
    """verify 는 gw 를 받지 않으므로(§6.1 시그니처 고정) 로직 판정용 GatewayClient 를 여기서 구성한다.
    LLM 경로는 오직 GatewayClient(SR-STACK-02); base_url 미지정 시 env(LITELLM_API_BASE) 폴백."""
    from sanity_llm import GatewayClient
    return GatewayClient(component="4", base_url=s.get("gateway_url"),
                         api_key=(s.get("budget") or {}).get("virtual_key"))

def _stdout_ref(rep) -> str | None:
    if not isinstance(rep, dict):
        return None
    return rep.get("stdout_ref") or (rep.get("diagnostics") or {}).get("stdout_ref")

def _llm_logic_blocked(s: dict, rep) -> bool:
    """로직 공격 재현 stdout 을 LLM 으로 판정 → 무력화 여부(bool). §00-8.4 텔레메트리 oracle 부재 보완."""
    from .prompts import LOGIC_VERIFY_SYSTEM
    from sanity_llm import wrap_untrusted
    v = _gw_for(s).complete_json(s["gateway_model"], system=LOGIC_VERIFY_SYSTEM,
            user=wrap_untrusted("tool_stdout", _json({"mode": "attack_replay", "stdout_ref": _stdout_ref(rep),
                "artifact_refs": rep.get("artifact_refs") if isinstance(rep, dict) else None})),
            trace_id=s["trace_id"], scope_id=s["scope_id"])
    return bool(v.get("blocked") or v.get("neutralized"))

def _llm_mission_ok(s: dict, rep) -> bool:
    """정상 미션(heartbeat/telemetry) stdout 을 LLM 으로 판정 → 무회귀 여부(bool)."""
    from .prompts import LOGIC_VERIFY_SYSTEM
    from sanity_llm import wrap_untrusted
    v = _gw_for(s).complete_json(s["gateway_model"], system=LOGIC_VERIFY_SYSTEM,
            user=wrap_untrusted("tool_stdout", _json({"mode": "normal_mission", "stdout_ref": _stdout_ref(rep),
                "artifact_refs": rep.get("artifact_refs") if isinstance(rep, dict) else None})),
            trace_id=s["trace_id"], scope_id=s["scope_id"])
    return bool(v.get("mission_ok") or v.get("no_regression"))
