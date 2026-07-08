# sanity_scenario_manager/path_extractor.py
from sanity_common.contracts import AttackPath
from sanity_common.state import State
import hashlib

def _gate_of(node: dict) -> str:
    if not (node.get("children") or []): return "LEAF"
    return (node.get("logic") or "AND").upper()

def enumerate_paths(tree: dict) -> list[list[dict]]:
    """모든 root-to-leaf 경로. 각 경로 = [root,...,leaf] 노드 dict 열(root→leaf 순)."""
    out: list[list[dict]] = []
    def dfs(n: dict, acc: list[dict]) -> None:
        acc = acc + [n]
        kids = n.get("children") or []
        if not kids: out.append(acc); return
        for c in kids: dfs(c, acc)     # AND·OR 모두 자식마다 분기(충족판정은 2.3; P1)
    dfs(tree, []); return out

class PathExtractor:
    def __init__(self, tree_id: str, tree: dict, state: State):
        self.tree_id = tree_id; self.tree = tree; self.state = state
        self._paths: list[AttackPath] = []; self._pi = 0; self._ni = 0

    def decompose(self) -> list[AttackPath]:                     # FR-SM-01
        aps: list[AttackPath] = []
        for rootleaf in enumerate_paths(self.tree):
            seq_nodes = list(reversed(rootleaf))                 # leaf→root (착수 순서)
            node_seq = [n["tnode_id"] for n in seq_nodes]        # §00-4 부여됨
            gate_seq = [_gate_of(n) for n in seq_nodes]
            pid = "p_" + hashlib.sha256((self.tree_id+"|".join(node_seq)).encode()).hexdigest()[:12]
            aps.append(AttackPath(path_id=pid, tree_id=self.tree_id,
                                  node_seq=node_seq, gate_seq=gate_seq))
        self._paths = aps
        self.state.r.rpush(f"st:path:{self.tree_id}", *[a.model_dump_json() for a in aps])
        return aps

    def _node_cost(self, n: dict) -> int:
        kids = n.get("children") or []
        if not kids: return 1
        cs = [self._node_cost(c) for c in kids]
        return 1 + (min(cs) if (n.get("logic","AND").upper()=="OR") else sum(cs))

    def rank_by_cost(self, paths: list[AttackPath]) -> None:     # FR-SM-02
        """경로를 '해당 leaf까지 root-to-leaf 노드수' 오름차순 정렬(최소비용 우선).
        OR 분기는 최소비용 대안이 앞서고, AND 분기는 형제 경로가 함께 필요(2.3 충족판정)."""
        # 각 leaf 경로의 대표 비용 = 경로 길이(선형) + 그 leaf가 속한 OR선택의 최소성 반영.
        paths.sort(key=lambda a: len(a.node_seq))
        # State의 경로 큐를 정렬 순서로 재적재
        self.state.r.delete(f"st:path:{self.tree_id}")
        self.state.r.rpush(f"st:path:{self.tree_id}", *[a.model_dump_json() for a in paths])
        self._paths = paths; self._pi = 0; self._ni = 0

    def current_path(self) -> AttackPath:
        return self._paths[self._pi]

    def next_node(self) -> dict | None:                          # 2.1.3 leaf→root 순
        """현재 경로의 다음 미착수 노드(dict)를 반환. 소진 시 None. 실행가능성 판정은 안 함(3.1 위임)."""
        ap = self.current_path()
        if self._ni >= len(ap.node_seq): return None
        tnode_id = ap.node_seq[self._ni]; self._ni += 1
        return self._resolve(tnode_id)                           # tnode_id → 실제 노드 객체

    def advance_path(self) -> bool:                              # 경로 소진 시 다음 경로(2.1 회귀)
        self._pi += 1; self._ni = 0
        return self._pi < len(self._paths)

    def _resolve(self, tnode_id: str) -> dict:
        """State의 tree에서 tnode_id로 노드 dict를 찾아 반환(FR-SM-03 핸드오프용 resolve)."""
        tree = self.state.get_tree(self.tree_id)
        found = {}
        def walk(n):
            if n.get("tnode_id")==tnode_id: found["n"]=n; return
            for c in n.get("children") or []: walk(c)
        walk(tree); return found["n"]
