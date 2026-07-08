# sanity_attacker/main.py
import os
import json
from sanity_common.aio import run_sync as _await          # MCP 코루틴 동기 실행(§00-2.1)
def _json(x): return json.dumps(x, ensure_ascii=False)     # 예시에서 쓰는 자명 헬퍼
from sanity_common.bus import Bus
from sanity_common.state import State
from sanity_common.toolset import Toolset
from sanity_llm import GatewayClient          # 6. Gateway 정본(gateway_log)
from sanity_log import LogWriter              # 7. Log 정본(gateway_log)
from .agent import build_graph, AttackerState

def run(scope_id: str) -> None:               # 동기(§00-2.1)
    """Allocator가 컨테이너를 스폰하며 scope_id를 env로 전달. dispatch 메시지 1건 소비 후 종료."""
    bus = Bus(); state = State(); log = LogWriter(component="3")   # 프로세스별 JSONL(§00-9)
    stream = f"sanity:dispatch:attacker:{scope_id}"
    for msg_id, p in bus.consume(stream, f"g:attacker:{scope_id}", scope_id):
        ts = Toolset(p["toolset_root"])                  # stdio Toolset(§00-8.5)
        gw = GatewayClient(component="3", base_url=p["gateway_url"],
                           api_key=p["budget"]["virtual_key"], log=log)  # 가상키만(SR-STACK-02)
        init = AttackerState(
            node=p["node"], compromise_ctx=p["compromise_ctx"], budget=p["budget"],
            workspace_root=p["workspace_root"], mav_endpoint=p["mav_endpoint"],  # Allocator 발급 workspace
            trace_id=p["trace_id"], scope_id=scope_id,
            tree_id=p["tree_id"], path_id=p["path_id"], gateway_model=p["gateway_model"],
            max_retry=p["max_retry"], retries=0)
        graph = build_graph(gw, ts, state, bus, log)
        graph.invoke(init)                           # 동기 LangGraph. 종료 시 status 이미 방출됨
        bus.ack(stream, f"g:attacker:{scope_id}", msg_id)
        return                                       # 노드당 1 인스턴스(FR-SR-CONCUR-02)

if __name__ == "__main__":
    run(os.environ["SANITY_SCOPE_ID"])
