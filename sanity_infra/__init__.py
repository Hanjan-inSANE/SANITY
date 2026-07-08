"""sanity_infra — SANITY 인프라 서버/러너 구현체(6/7 제외; gateway_log가 담당).

  - dah/     : 0. DAH Interface 러너 — TM(1) 실행 → sanity:tree:inbox 발행 (§00-2.2)
  - toolset/ : Toolset MCP 서버(8) — 별도 세션
  - target/  : DVD(ArduPilot SITL) 배포(9) — 별도 세션
"""

__version__ = "0.1.0"
