# sanity_defender/main.py
import os
import json
from sanity_common.aio import run_sync as _await          # MCP 코루틴 동기 실행(§00-2.1)
def _json(x): return json.dumps(x, ensure_ascii=False)
from sanity_common.bus import Bus
from sanity_common.state import State
from sanity_common.toolset import Toolset
from sanity_llm import GatewayClient          # 6. Gateway 정본(gateway_log)
from sanity_log import LogWriter              # 7. Log 정본(gateway_log)
from .agent import build_graph, DefenderState

def run(scope_id: str) -> None:               # 동기(§00-2.1)
    bus = Bus(); state = State(); log = LogWriter(component="4")   # 프로세스별 JSONL(§00-9)
    stream = f"sanity:dispatch:defender:{scope_id}"
    for msg_id, p in bus.consume(stream, f"g:defender:{scope_id}", scope_id):
        ts = Toolset(p["toolset_root"])                  # stdio Toolset(§00-8.5)
        gw = GatewayClient(component="4", base_url=p["gateway_url"],
                           api_key=p["budget"]["virtual_key"], log=log)  # 가상키만(SR-STACK-02)
        init = DefenderState(
            attack_context=p["attack_context"], budget=p["budget"], trace_id=p["trace_id"],
            scope_id=scope_id, tree_id=p["tree_id"], gateway_model=p["gateway_model"],
            workspace_root=p["workspace_root"], mav_endpoint=p["mav_endpoint"],  # Attacker와 동일 workspace
            max_retry=p["max_retry"], retries=0)
        build_graph(gw, ts, state, bus, log).invoke(init)  # 동기 LangGraph
        bus.ack(stream, f"g:defender:{scope_id}", msg_id)
        return                                   # 침해 노드당 1 인스턴스(FR-SR-CONCUR-02)

if __name__ == "__main__":
    run(os.environ["SANITY_SCOPE_ID"])
