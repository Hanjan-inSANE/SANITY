"""sanity_defender — 컴포넌트 4: Defender (침해 노드 수준 방어 에이전트).

침해 노드당 1 인스턴스(FR-SR-CONCUR-02). AttackContext 는 Task Manager(2.3.3)가 dispatch·주입한 것만
수신한다 — Attacker 로부터 직접 받지 않는다(FR-SR-CONCUR-03). 방어는 Allocator 발급 workspace(clone)에만
적용하고 원본은 무방어 유지(FR-DF-03). 검증 성공 = 무력화 ∧ 무회귀(FR-DF-05).
계약·버스·State·Toolset·Gateway·Log 는 전부 sanity_common / sanity_llm / sanity_log 에서 import(재정의 금지).

레이아웃:
  - main.py        : 엔트리(dispatch:defender:{scope_id} 소비 → 그래프 1회 실행)
  - agent.py       : LangGraph StateGraph (4.1→4.2→4.3, 재방어 루프)
  - env_adapter.py : 4.1 (FR-DF-01)
  - executor.py    : 4.2 (FR-DF-02/03)
  - verifier.py    : 4.3 (FR-DF-04/05, 6-게이트 + compare_baseline)
  - prompts.py     : LLM 프롬프트(대상/PoV/RAG 텍스트는 wrap_untrusted 로만 주입)
"""

__version__ = "0.1.0"
