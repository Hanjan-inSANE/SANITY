"""sanity_scenario_manager — 컴포넌트 2: Scenario Manager (트리 수준 제어 평면).

트리당 1 인스턴스(FR-SR-CONCUR-01). 오케스트레이션 권한은 Task Manager(2.3)에 단독 귀속(FR-SR-CONCUR-03).
계약·버스·State·Toolset·Gateway·Log 는 전부 sanity_common / sanity_llm / sanity_log 에서 import 한다(재정의 금지).

레이아웃:
  - main.py            : 엔트리(sanity:tree:inbox 소비 → 트리당 ScenarioManager 스레드 스폰)
  - manager.py         : ScenarioManager (트리 1개 생명주기)
  - path_extractor.py  : 2.1 Path Extractor (FR-SM-01/02)
  - allocator.py       : 2.2 Allocator (FR-SM-03/04/05)
  - task_manager.py    : 2.3 Task Manager (FR-SM-06..10, 오케스트레이션 단독 권한)
  - submitter.py       : 2.4 Submitter (FR-SM-11/12)
"""

__version__ = "0.1.0"
