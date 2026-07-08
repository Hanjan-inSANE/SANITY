# sanity_attacker/agent.py
import json
from sanity_common.aio import run_sync as _await          # MCP 코루틴 동기 실행(§00-2.1)
def _json(x): return json.dumps(x, ensure_ascii=False)     # 예시에서 쓰는 자명 헬퍼
from typing import TypedDict
from langgraph.graph import StateGraph, END

class AttackerState(TypedDict, total=False):
    # 입력 (Allocator dispatch)
    node: dict; compromise_ctx: dict; budget: dict
    workspace_root: str; mav_endpoint: str        # Toolset workspace(공유 볼륨 경로) + 로직 SITL 엔드포인트
    trace_id: str; scope_id: str; tree_id: str; path_id: str
    gateway_model: str; max_retry: int; retries: int
    # 3.1 산출
    surface: dict                 # {protocols, interfaces, entrypoints, footholds, harness}
    selected_tools: list[dict]    # ToolDescriptor[] (real registry)
    attack_class: str             # "crash" | "logic"  ← 선택 도구가 결정(FR-AT-05)
    feasible: bool; fuzz_mode: str
    # 3.2 산출
    seed_ref: str                 # 결정론 replay용 입력(crash=input_blob_ref, logic=시퀀스 파일)
    target_cmd: list              # crash: 빌드된 바이너리 실행 argv
    signals: dict                 # 관측 결과(crash: reproduce_pov/collect_findings; logic: run_tool stdout 파싱)
    # 3.3 산출
    success: bool; pov: dict

def build_graph(gw, ts, state, bus, log):
    from .env_adapter import parse_context, select_tools, prepare_toolset
    from .executor import gen_seed, run_exploit               # observe 노드 삭제(§5.3)
    from .verifier import judge, record_and_emit, emit_fail

    g = StateGraph(AttackerState)
    g.add_node("parse",    lambda s: parse_context(s, log))                 # 3.1.1
    g.add_node("select",   lambda s: select_tools(s, gw, ts, log))         # 3.1.2 (LLM) → attack_class
    g.add_node("prepare",  lambda s: prepare_toolset(s, log))              # 3.1.3 (Allocator workspace 재사용)
    g.add_node("seed",     lambda s: gen_seed(s, gw, log))                 # 3.2.1 (LLM)
    g.add_node("exploit",  lambda s: run_exploit(s, ts, log))             # 3.2.2 (실제 Toolset: build/fuzz/reproduce_pov/run_tool)
    g.add_node("judge",    lambda s: judge(s, gw, log))                   # 3.3.1 (신호는 exploit에서 수집됨)
    g.add_node("record",   lambda s: record_and_emit(s, state, bus, log))# 3.3.2 성공 → status+AttackContext
    g.add_node("fail",     lambda s: emit_fail(s, bus, log))             # FAIL → 2.3

    g.set_entry_point("parse")
    g.add_edge("parse", "select")
    g.add_conditional_edges("select", lambda s: "prepare" if s["feasible"] else "fail",
                            {"prepare": "prepare", "fail": "fail"})        # 실행불가 → FAIL(FR-AT-01)
    g.add_edge("prepare", "seed"); g.add_edge("seed", "exploit")
    g.add_edge("exploit", "judge")                                        # observe 제거(신호는 exploit에서)
    g.add_conditional_edges("judge", _after_judge,
                            {"record": "record", "retry": "seed", "fail": "fail"})
    g.add_edge("record", END); g.add_edge("fail", END)
    return g.compile()

def _after_judge(s: AttackerState) -> str:
    if s.get("success"): return "record"
    if s["retries"] < s["max_retry"]:                 # FR-SR-BUDGET-02 (예산 소진도 fail로 수렴)
        s["retries"] += 1; return "retry"
    return "fail"
