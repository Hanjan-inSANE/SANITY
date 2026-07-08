# sanity_defender/agent.py
import json
from sanity_common.aio import run_sync as _await          # MCP 코루틴 동기 실행(§00-2.1)
def _json(x): return json.dumps(x, ensure_ascii=False)
from typing import TypedDict
from langgraph.graph import StateGraph, END

class DefenderState(TypedDict, total=False):
    attack_context: dict; budget: dict; trace_id: str; scope_id: str; tree_id: str
    gateway_model: str; max_retry: int; retries: int
    workspace_root: str; mav_endpoint: str        # Attacker와 동일 workspace(crash) + 방어검증 SITL(logic)
    gateway_url: str; _pov: dict; _target_files: list   # 런타임 내부 채널(필수 선언)
    # 4.1 산출
    attack_class: str            # "crash" | "logic"  ← select_defense가 PoV.tool kind로 파생(§00-3.1)
    defense_kind: str            # "source_patch" | "config_harden"
    selected_tools: list[dict]
    # 4.2 산출
    root_cause: dict; diff: str; patch_ref: str; patched_build_ref: str; target_cmd: list
    # 4.3 산출 (compare_baseline 6 게이트)
    baseline_pov_reproduces: bool; patched_pov_blocked: bool; patched_build_success: bool
    regression_tests_pass: bool; no_new_sanitizer_finding_on_replay: bool; evidence_bundle_complete: bool
    neutralized: bool; no_regression: bool; success: bool; patch: dict; bundle_ref: str

def build_graph(gw, ts, state, bus, log):
    from .env_adapter import parse_ctx, select_defense, prepare_toolset
    from .executor import locate, generate, apply_and_build
    from .verifier import verify, emit_patch, emit_fail       # reset_replay 삭제(verify가 재빌드+재현 포함)

    g = StateGraph(DefenderState)
    g.add_node("parse",    lambda s: parse_ctx(s, log))               # 4.1.1
    g.add_node("select",   lambda s: select_defense(s, gw, ts, log))  # 4.1.2 (LLM, 클래스별)
    g.add_node("prepare",  lambda s: prepare_toolset(s, log))         # 4.1.3 (Allocator workspace 재사용, 생성 금지)
    g.add_node("locate",   lambda s: locate(s, gw, log))              # 4.2.1 (crash=root cause / logic=정책대상)
    g.add_node("generate", lambda s: generate(s, gw, log))            # 4.2.2
    g.add_node("apply",    lambda s: apply_and_build(s, ts, log))     # 4.2.3 (apply_patch + patched build)
    g.add_node("verify",   lambda s: verify(s, ts, log))              # 4.3 (6게이트 계산 + compare_baseline)
    g.add_node("patch",    lambda s: emit_patch(s, state, bus, log))  # 성공 → Patch+status → 2.3
    g.add_node("fail",     lambda s: emit_fail(s, bus, log))

    g.set_entry_point("parse")
    for a,b in [("parse","select"),("select","prepare"),("prepare","locate"),
                ("locate","generate"),("generate","apply"),("apply","verify")]:
        g.add_edge(a,b)
    g.add_conditional_edges("verify", _after_verify,
                            {"patch":"patch","redefend":"locate","fail":"fail"})  # (a)만이면 재방어(4.2)
    g.add_edge("patch", END); g.add_edge("fail", END)
    return g.compile()

def _after_verify(s: DefenderState) -> str:
    if s.get("success"): return "patch"           # 무력화 ∧ 무회귀
    if s["retries"] < s["max_retry"]:              # FR-SR-BUDGET-02
        s["retries"] += 1; return "redefend"       # (a)만 만족(무력화됐으나 회귀) → 4.2 재방어
    return "fail"
