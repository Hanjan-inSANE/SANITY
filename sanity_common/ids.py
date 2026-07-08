# sanity_common/ids.py
import hashlib, json
from typing import Any

_VOLATILE = {"tnode_id"}   # id 부여 전에는 없지만, 재계산 시 제외해야 안정적

def canonical_json(node: dict) -> str:
    """볼라틸 필드를 제외하고 키 정렬하여 결정론적 직렬화."""
    def prune(n: Any) -> Any:
        if isinstance(n, dict):
            return {k: prune(v) for k, v in sorted(n.items()) if k not in _VOLATILE}
        if isinstance(n, list):
            return [prune(x) for x in n]
        return n
    return json.dumps(prune(node), ensure_ascii=False, sort_keys=True, separators=(",", ":"))

def tree_id_of(tree: dict) -> str:
    """tree_id = sha256(정규직렬화)[:16]. SM 인스턴스화 시 1회."""
    return "t_" + hashlib.sha256(canonical_json(tree).encode("utf-8")).hexdigest()[:16]

def canon_node_hash(node: dict) -> str:
    keep = {k: node.get(k) for k in ("summary","attack_context","logic")}
    keep["evidence"] = sorted([e.get("id","") for e in (node.get("evidence") or [])])
    return hashlib.sha256(json.dumps(keep, ensure_ascii=False, sort_keys=True).encode()).hexdigest()[:16]

def assign_tnode_ids(tree: dict, *, dag_mode: bool = False) -> dict:
    """트리를 in-place로 순회하며 각 노드에 tnode_id 주입. 루트="r".
    반환: 같은 tree 객체(체이닝). 동일 입력 → 동일 부여(멱등)."""
    def walk(n: dict, path: str) -> None:
        n["tnode_id"] = ("h:" + canon_node_hash(n)) if dag_mode else path
        for k, c in enumerate(n.get("children") or []):
            walk(c, f"{path}/{k}")
    walk(tree, "r")
    return tree
