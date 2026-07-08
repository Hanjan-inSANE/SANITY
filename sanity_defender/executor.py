# sanity_defender/executor.py
import os
import json
from sanity_common.aio import run_sync as _await          # MCP 코루틴 동기 실행(§00-2.1)
def _json(x): return json.dumps(x, ensure_ascii=False)

def locate(s: dict, gw, log) -> dict:
    from .prompts import ROOTCAUSE_SYSTEM, POLICY_SYSTEM
    from sanity_llm import wrap_untrusted                     # §00-7.4
    pov = s["_pov"]
    if s["attack_class"] == "crash":
        crash = wrap_untrusted("pov_crash", _json({"crash_report_ref": pov.get("crash_report_ref"),
                    "signature": pov["exploit_signature"], "effect": pov["effect"]}))
        # 선택 KB(5) RAG 참조: 기존 threat_modeler/attack_rag.py 클라이언트 재사용 가능(4.2.1 선택)
        rc = gw.complete_json(s["gateway_model"], user=crash, system=ROOTCAUSE_SYSTEM,
                              trace_id=s["trace_id"], scope_id=s["scope_id"])
        return {"root_cause": rc}                       # {"files":[...], "func":..., "reason":...}
    else:
        pol = wrap_untrusted("pov_logic", _json({"signature": pov["exploit_signature"],
                    "effect": pov["effect"], "sequence": pov.get("sequence")}))
        rc = gw.complete_json(s["gateway_model"], user=pol, system=POLICY_SYSTEM,
                              trace_id=s["trace_id"], scope_id=s["scope_id"])
        return {"root_cause": rc}                       # {"params":[...], "signing":bool, "rules":[...]}

def generate(s: dict, gw, log) -> dict:
    """crash=Patch(DM-7) unified diff, 로직=config/규칙 diff 생성."""
    from .prompts import PATCH_SYSTEM, HARDEN_SYSTEM
    sys = PATCH_SYSTEM if s["attack_class"]=="crash" else HARDEN_SYSTEM
    gen = gw.complete_json(s["gateway_model"], user=_json({"root_cause": s["root_cause"]}),
                           system=sys, trace_id=s["trace_id"], scope_id=s["scope_id"])
    # gen = {"diff": "<unified diff | config/rule diff>", "target_files":[...]}
    return {"diff": gen["diff"], "_target_files": gen.get("target_files", [])}

def apply_and_build(s: dict, ts, log) -> dict:
    ws = s["workspace_root"]; tid = s["trace_id"]
    if s["attack_class"] == "crash":
        ap = _await(ts.diag("apply_patch", {"workspace_root": ws, "patch_text": s["diff"], "trace_id": tid}))
        b  = _await(ts.diag("build", {"workspace_root": ws, "build_system":"auto",
                    "build_dir":"build_patched", "sanitizer":"asan", "trace_id": tid}))   # baseline은 build/ 유지
        ok = b.get("exit_code", 1) == 0
        return {"patch_ref": ap.get("patch_ref"), "patched_build_ref": b.get("build_artifact_ref"),
                "target_cmd": _target_cmd_of(ws, b, build_dir="build_patched"), "patched_build_success": ok}
    else:   # logic: config 하드닝을 run_tool로 적용(방어검증용 SITL에)
        tool_id = s["selected_tools"][0]["tool_id"]
        r = _await(ts.diag("run_tool", {"workspace_root": ws, "tool_id": tool_id,
                   "params": {"mav_endpoint": s["mav_endpoint"], **_harden_params(s["diff"])}, "trace_id": tid}))
        return {"patch_ref": r.get("artifact_refs",[None])[0], "patched_build_success": r.get("exit_code")==0,
                "target_cmd": []}

# --- 로컬 순수 헬퍼(정의 고정, 재발명 아님; §7 로컬 헬퍼) ---
def _target_cmd_of(ws: str, build_diag: dict, build_dir: str = "build") -> list:
    """빌드 산출 바이너리 실행 argv 를 도출한다(03과 동일).
    build_diag['build_artifact_ref'] 가 실행파일 경로면 그대로, 아니면 {ws}/{build_dir} 하위 관례 경로."""
    ref = (build_diag or {}).get("build_artifact_ref") or ""
    binname = os.path.basename(ref) if ref else ""
    if ref and ("/" in ref or "\\" in ref) and not ref.startswith(("artifact://",)):
        return [ref]                                        # 이미 실행파일 경로
    if binname and not binname.startswith("artifact"):
        return [f"{ws}/{build_dir}/{binname}"]
    return [f"{ws}/{build_dir}/a.out"]                      # 관례 기본 바이너리

def _harden_params(diff: str) -> dict:
    """config 하드닝 diff → run_tool params dict. diff가 JSON 객체면 그대로 params로,
    아니면 원문 diff를 config_diff 키로 전달(도구가 파싱)."""
    try:
        obj = json.loads(diff)
        if isinstance(obj, dict):
            return obj
    except (ValueError, TypeError):
        pass
    return {"config_diff": diff}
