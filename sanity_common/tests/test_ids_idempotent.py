# sanity_common/tests/test_ids_idempotent.py
# §4 검증절 / REQ INV-4: assign_tnode_ids 멱등성 + tree_id 결정론.
import copy
import pytest

from sanity_common.ids import assign_tnode_ids, tree_id_of, canonical_json


def _sample_tree() -> dict:
    return {
        "summary": "root goal",
        "attack_context": "ctx",
        "evidence": [{"id": "e2", "note": "b"}, {"id": "e1", "note": "a"}],
        "logic": "OR",
        "children": [
            {
                "summary": "child A",
                "logic": "AND",
                "children": [
                    {"summary": "leaf A0", "evidence": []},
                    {"summary": "leaf A1"},
                ],
            },
            {"summary": "child B (leaf)"},
        ],
    }


def _collect_ids(node: dict) -> dict:
    """구조적 경로 → tnode_id 매핑을 수집(위치 기준으로 안정 비교)."""
    out = {}

    def walk(n: dict, path: str) -> None:
        out[path] = n["tnode_id"]
        for k, c in enumerate(n.get("children") or []):
            walk(c, f"{path}/{k}")

    walk(node, "r")
    return out


@pytest.mark.parametrize("dag_mode", [False, True])
def test_assign_tnode_ids_idempotent(dag_mode: bool):
    """같은 트리에 두 번 호출해도 모든 tnode_id 가 불변(멱등)."""
    tree = _sample_tree()

    assign_tnode_ids(tree, dag_mode=dag_mode)
    first = _collect_ids(tree)

    # 두 번째 호출: 첫 호출로 주입된 tnode_id 가 그대로 있는 상태에서 재부여.
    assign_tnode_ids(tree, dag_mode=dag_mode)
    second = _collect_ids(tree)

    assert first == second, "assign_tnode_ids must be idempotent"
    # 모든 노드가 실제로 id 를 받았는지도 확인.
    assert all(v for v in second.values())


def test_pure_tree_mode_path_ids():
    """순수 트리 모드: tnode_id 는 구조적 경로('r', 'r/0', 'r/0/1', ...)."""
    tree = _sample_tree()
    assign_tnode_ids(tree, dag_mode=False)
    assert tree["tnode_id"] == "r"
    assert tree["children"][0]["tnode_id"] == "r/0"
    assert tree["children"][0]["children"][1]["tnode_id"] == "r/0/1"
    assert tree["children"][1]["tnode_id"] == "r/1"


def test_dag_mode_hash_ids():
    """DAG 모드: tnode_id 는 'h:'+canon_node_hash 접두."""
    tree = _sample_tree()
    assign_tnode_ids(tree, dag_mode=True)
    assert tree["tnode_id"].startswith("h:")


def test_tree_id_deterministic_and_ignores_tnode_id():
    """tree_id 는 결정론적이며, 부여된 tnode_id(볼라틸)에 영향을 받지 않는다."""
    a = _sample_tree()
    b = copy.deepcopy(a)

    id_before = tree_id_of(a)
    assign_tnode_ids(a, dag_mode=False)  # tnode_id 주입 후에도 tree_id 불변이어야 함
    id_after = tree_id_of(a)

    assert id_before == id_after == tree_id_of(b)
    assert id_before.startswith("t_")


def test_tree_id_distinguishes_different_trees():
    a = _sample_tree()
    b = _sample_tree()
    b["summary"] = "different root goal"
    assert tree_id_of(a) != tree_id_of(b)


def test_canonical_json_prunes_tnode_id():
    """canonical_json 은 tnode_id 볼라틸 필드를 제외한다."""
    tree = _sample_tree()
    before = canonical_json(tree)
    assign_tnode_ids(tree, dag_mode=False)
    after = canonical_json(tree)
    assert before == after
    assert "tnode_id" not in after
