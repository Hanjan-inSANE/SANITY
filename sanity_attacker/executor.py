# sanity_attacker/executor.py
import os
import json
from sanity_common.aio import run_sync as _await          # MCP 코루틴 동기 실행(§00-2.1)
def _json(x): return json.dumps(x, ensure_ascii=False)     # 예시에서 쓰는 자명 헬퍼

def gen_seed(s: dict, gw, log) -> dict:
    from .prompts import SEED_SYSTEM
    from sanity_llm import wrap_untrusted
    user = wrap_untrusted("node", _json({"surface": s["surface"], "attack_class": s["attack_class"],
                                         "mode": s.get("fuzz_mode")}))
    seed = gw.complete_json(s["gateway_model"], user=user, system=SEED_SYSTEM,
                            trace_id=s["trace_id"], scope_id=s["scope_id"])
    # seed = {"payload":..., "protocol":..., "sequence":[...]} 클래스별
    seed_ref = _persist_seed(s["workspace_root"], seed)   # 공유 workspace의 seeds/ 에 기록(결정론 replay 입력)
    return {"seed_ref": seed_ref}

def run_exploit(s: dict, ts, log) -> dict:
    ws = s["workspace_root"]; tid = s["trace_id"]
    if s["attack_class"] == "crash":
        # 1) build(asan) → 2) (harness면)fuzz+collect or seed 직접 → 3) reproduce_pov → 4) run_sanitizer
        build = _await(ts.diag("build", {"workspace_root": ws, "build_system":"auto", "build_dir":"build", "sanitizer":"asan", "trace_id": tid}))
        target_cmd = _target_cmd_of(ws, build, build_dir="build")   # build_artifact_ref→바이너리 argv
        input_ref = None
        if s.get("fuzz_mode") == "whitebox" and s["surface"].get("harness"):
            fuzz_out = f"artifacts/fuzz/{tid}"                       # start_fuzz·collect_findings 공유 경로(정본)
            _await(ts.diag("build_harness", {"workspace_root": ws, "harness_path": s["surface"]["harness"], "trace_id": tid}))
            _await(ts.diag("start_fuzz", {"workspace_root": ws, "tool_id":"aflpp", "target_cmd": target_cmd,
                    "seeds_dir": _seeds_dir(ws), "output_dir": fuzz_out, "timeout_sec": _fuzz_budget(s), "trace_id": tid}))
            find = _await(ts.diag("collect_findings", {"workspace_root": ws, "fuzz_output_dir": fuzz_out, "trace_id": tid}))
            input_ref = find.get("crash_report_ref") if find.get("crash_count", 0) > 0 else None
        input_ref = input_ref or s["seed_ref"]                       # 퍼즈 크래시 없으면 LLM seed로 직접 재현
        _okr, rep = _await(ts.sig("reproduce_pov", {"workspace_root": ws, "target_cmd": target_cmd,
                     "input_blob_ref": input_ref, "trace_id": tid}))  # ⚠ sig: 크래시=ok False라 diag 금지
        reproduced = bool(rep.get("reproduced"))
        san_finding = False
        if reproduced:
            _oks, san = _await(ts.sig("run_sanitizer", {"workspace_root": ws, "sanitizer":"asan", "target_cmd": target_cmd, "trace_id": tid}))
            san_finding = bool(san.get("finding_observed"))          # 정본 키: finding_observed
        signals = {"reproduced": reproduced, "pov_ref": rep.get("pov_ref"), "exit_code": rep.get("exit_code"),
                   "sanitizer_finding": san_finding, "input_blob_ref": input_ref, "crash_report_ref": rep.get("pov_ref")}
        return {"target_cmd": target_cmd, "seed_ref": input_ref, "signals": signals}
    else:  # logic/protocol: run_tool로 실제 도구 실행(pymavlink_inject/gps_input_spoof 등). oracle 없음(§00-8.4).
        tool_id = _primary_logic_tool(s["selected_tools"])
        resp = _await(ts.call("run_tool", {"workspace_root": ws, "tool_id": tool_id,   # call: 봉투 전체 필요
                      "params": {"mav_endpoint": s["mav_endpoint"], "seed_ref": s["seed_ref"]}, "trace_id": tid}))
        d = resp.get("diagnostics", {})
        signals = {"stdout_ref": d.get("stdout_ref"), "artifact_refs": resp.get("artifact_refs", []),  # artifact_refs=봉투필드
                   "exit_code": d.get("exit_code"), "input_blob_ref": s["seed_ref"]}
        return {"target_cmd": [], "seed_ref": s["seed_ref"], "signals": signals}

# --- 로컬 순수 헬퍼(정의 고정, 재발명 아님; §7 로컬 헬퍼) ---
def _seeds_dir(ws: str) -> str:
    return f"{ws}/seeds"

def _persist_seed(ws: str, seed: dict) -> str:
    """seed 를 공유 workspace 의 seeds/ 에 결정론적으로 기록하고 그 경로(ref)를 반환(replay 입력)."""
    d = _seeds_dir(ws); os.makedirs(d, exist_ok=True)
    import hashlib
    blob = _json(seed)
    name = "seed_" + hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16] + ".json"
    path = f"{d}/{name}"
    with open(path, "w", encoding="utf-8") as f:
        f.write(blob)
    return path

def _fuzz_budget(s: dict) -> int:
    """예산(DM-11 budget)의 wall_clock_s 를 fuzz timeout(초)으로 사상. 미지정 시 보수적 기본값."""
    wc = (s.get("budget") or {}).get("wall_clock_s")
    return int(wc) if wc else 3600

def _target_cmd_of(ws: str, build_diag: dict, build_dir: str = "build") -> list:
    """빌드 산출 바이너리 실행 argv 를 도출한다.
    build_diag['build_artifact_ref'] 가 실행파일 경로면 그대로, 아니면 {ws}/{build_dir} 하위 관례 경로."""
    ref = (build_diag or {}).get("build_artifact_ref") or ""
    binname = os.path.basename(ref) if ref else ""
    if ref and ("/" in ref or "\\" in ref) and not ref.startswith(("artifact://",)):
        return [ref]                                        # 이미 실행파일 경로
    if binname and not binname.startswith("artifact"):
        return [f"{ws}/{build_dir}/{binname}"]
    return [f"{ws}/{build_dir}/a.out"]                      # 관례 기본 바이너리

def _primary_logic_tool(tools: list) -> str:
    """선택 도구 중 로직 실행 우선순위(network_attacker > network_scanner > 그 외)의 tool_id."""
    for kind in ("network_attacker", "network_scanner"):
        for t in tools:
            if t.get("kind") == kind:
                return t["tool_id"]
    return tools[0]["tool_id"] if tools else ""
