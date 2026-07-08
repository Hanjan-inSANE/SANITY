# sanity_scenario_manager/manager.py
from sanity_common.bus import Bus
from sanity_common.state import State
from sanity_common.config import SanityConfig
from .path_extractor import PathExtractor
from .allocator import Allocator
from .task_manager import TaskManager
from .submitter import Submitter

class ScenarioManager:
    def __init__(self, tree_id: str, tree: dict, cfg: SanityConfig, bus: Bus, state: State):
        self.tree_id = tree_id; self.tree = tree; self.cfg = cfg; self.bus = bus; self.state = state
        self.pe = PathExtractor(tree_id, tree, state)
        self.alloc = Allocator(tree_id, cfg, bus, state)
        self.tm = TaskManager(tree_id, tree, cfg, bus, state, self.alloc, self.pe)
        self.sub = Submitter(tree_id, cfg, bus, state)
        # 미완 인스턴스 카운터 + 종료 플래그(정상 종료·부분제출 판정용, MAJOR-1/MINOR-5)
        self._pending_att = 0; self._pending_def = 0
        self._root_done = False; self._exhausted = False

    # 상태 종류 분류(카운터 감소용). attacker 종료 상태는 att-, defender 종료 상태는 def-.
    _ATT_TERMINAL = {"DISPATCH_DEFENDER", "ATTACK_NEXT", "ROOT_DONE", "PATH_ABORT", "PATH_ALT"}
    _DEF_TERMINAL = {"COLLECT", "DEF_FAILED"}

    def run(self) -> None:                          # 동기(자기 스레드에서 실행)
        paths = self.pe.decompose()                 # 2.1.1 → [AttackPath] (State에 큐 적재)
        self.pe.rank_by_cost(paths)                 # 2.1.2 최단(최소비용) 우선 정렬
        self._drive_current_path()                  # 첫 경로의 노드 착수(pending_att++)
        if self._terminated(): self.sub.finalize(); return   # 빈/무경로 트리 즉시 종결
        # 블로킹 상태-소비 루프: 에이전트 status 수신 → TaskManager 처리 → 다음 행동
        for msg_id, obj in self.bus.consume(f"sanity:status:{self.tree_id}",
                                            f"g:sm:{self.tree_id}", "sm"):
            action = self.tm.on_status(obj)         # 2.3 (§5) → 반환: 다음 행동 지시
            if action.kind in self._ATT_TERMINAL: self._pending_att -= 1   # 방금 보고한 attacker 종료
            if action.kind in self._DEF_TERMINAL: self._pending_def -= 1   # 방금 보고한 defender 종료
            if action.kind == "ROOT_DONE" or action.root_done: self._root_done = True
            self._apply(action)                      # 새 att/def 스폰 시 카운터 증가
            self.bus.ack(f"sanity:status:{self.tree_id}", f"g:sm:{self.tree_id}", msg_id)
            if self._terminated():                   # root 달성 or 경로 소진 + 진행 중 인스턴스 0
                self.sub.finalize(); return          # MAJOR-1: 디스패치한 Defender까지 보고 후 제출

    def _terminated(self) -> bool:
        return (self._root_done or self._exhausted) and self._pending_att == 0 and self._pending_def == 0

    def _drive_current_path(self) -> None:
        node = self.pe.next_node()                  # 2.1.3 leaf→root 다음 노드
        if node is None:                            # 경로 소진 → 다음 경로(2.1로 회귀)
            if not self.pe.advance_path(): self._exhausted = True; return   # 모든 경로 소진
            node = self.pe.next_node()
            if node is None: self._exhausted = True; return
        self.alloc.spawn_attacker(node, self.pe.current_path()); self._pending_att += 1   # 2.2 (§4)

    def _apply(self, action) -> None:
        # action.kind ∈ {ATTACK_NEXT, DISPATCH_DEFENDER, PATH_ABORT, PATH_ALT, COLLECT, DEF_FAILED, ROOT_DONE, NOOP}
        if action.kind == "DISPATCH_DEFENDER":
            # M2: unique 성공 PoV 수집 → Submitter (dedup 통과 성공 아티팩트, FR-SM-11)
            self.sub.collect({"kind": "pov", "pov_id": action.attack_ctx.pov.pov_id})
            self.alloc.spawn_defender(action.attack_ctx); self._pending_def += 1   # 2.3.3 단독(FR-SR-CONCUR-03)
            if not action.root_done:                                    # B3: root 미달성이면 공격 계속
                self._drive_current_path()
        elif action.kind in ("ATTACK_NEXT", "PATH_ALT", "PATH_ABORT"):
            self._drive_current_path()
        elif action.kind == "COLLECT":              # Defender 성공 아티팩트(patch) 수집
            self.sub.collect(action.artifact)
        # ROOT_DONE / DEF_FAILED / NOOP: 새 스폰 없음(카운터는 run에서 이미 반영)
