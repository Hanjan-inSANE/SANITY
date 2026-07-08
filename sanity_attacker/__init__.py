"""sanity_attacker — 컴포넌트 3: Attacker (노드 수준 공격 에이전트).

노드당 1 인스턴스(FR-SR-CONCUR-02). Defender 를 직접 호출하지 않는다(FR-SR-CONCUR-03) —
성공 시 AttackContext 를 status 와 함께 2.3(Task Manager)으로만 방출한다.
계약·버스·State·Toolset·Gateway·Log 는 전부 sanity_common / sanity_llm / sanity_log 에서 import(재정의 금지).

레이아웃:
  - main.py        : 엔트리(dispatch:attacker:{scope_id} 소비 → 그래프 1회 실행)
  - agent.py       : LangGraph StateGraph (3.1→3.2→3.3, 재시도 루프)
  - env_adapter.py : 3.1 Env. Adapter (FR-AT-01/02)
  - executor.py    : 3.2 Executor (FR-AT-03/04)
  - verifier.py    : 3.3 Verifier (FR-AT-05/06)
  - prompts.py     : LLM 시스템 프롬프트(대상/RAG 텍스트는 wrap_untrusted 로만 주입)
"""

__version__ = "0.1.0"
