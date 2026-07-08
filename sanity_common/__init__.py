"""sanity_common — SANITY 공용 계약 & 인프라 라이브러리 (00_COMMON_CONTRACTS 정본).

세 컴포넌트(2/3/4)가 공유하는 단일 정본:
  - contracts : DM-1..DM-11 pydantic 모델 + 공격 클래스 파생 (§3, §3.1)
  - ids       : tnode_id/tree_id 결정론적 부여 (§4)
  - bus       : Redis Streams 메시지 버스 (§5)
  - state     : State Store(Redis) + exploit_signature (§6)
  - toolset   : Toolset stdio MCP 클라이언트 (§8.5)
  - aio       : run_sync (async→sync 브리지) (§2.1)
  - config    : SanityConfig + load_config (§11)
  - errors    : 공용 예외 계층

서브모듈은 필요한 것만 직접 import 한다. 예: `from sanity_common.contracts import PoV`.
(bus/state/toolset 는 redis/mcp 런타임 의존이 있으므로 최상위 __init__ 에서 강제 import 하지 않는다.)
"""

__version__ = "0.1.0"
