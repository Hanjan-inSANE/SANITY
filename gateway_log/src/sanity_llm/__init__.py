"""6. LLM Gateway 클라이언트 라이브러리.

에이전트(1·3·4)는 이 라이브러리로만 AI를 부른다.

사용 예:
    from sanity_llm import GatewayClient
    from sanity_log import LogWriter

    log = LogWriter(component="3")
    gw = GatewayClient(component="3", log=log)
    res = gw.complete("sane-sonnet", user="분석해줘...",
                      trace_id="tree3-path2", scope_id="tree3.node7.attacker")
    print(res.text, res.cost_usd)

    # JSON을 받아야 할 때(위협모델러 등):
    tree = gw.complete_json("sane-sonnet", user="...공격트리 JSON으로...")
"""
from .client import GatewayClient, LLMResult
from .budget import issue_key
from .safety import wrap_untrusted        # SR-SEC-01 프롬프트 인젝션 방어
from . import errors

__all__ = ["GatewayClient", "LLMResult", "issue_key", "wrap_untrusted", "errors"]
