# sanity_common/state.py
import json, os
import redis
from .contracts import InstanceState, CompromiseContext

class State:
    def __init__(self, url: str | None = None):       # DB 1 = 상태 (버스는 DB 0)
        url = url or os.getenv("REDIS_URL_STATE", "redis://redis:6379/1")
        self.r = redis.Redis.from_url(url, decode_responses=True)
    # --- 트리 영속 ---
    def put_tree(self, tree_id: str, tree: dict) -> None:
        self.r.set(f"st:tree:{tree_id}", json.dumps(tree, ensure_ascii=False))
    def get_tree(self, tree_id: str) -> dict | None:
        v = self.r.get(f"st:tree:{tree_id}"); return json.loads(v) if v else None
    # --- 인스턴스 상태 (DM-5) ---
    def set_state(self, s: InstanceState) -> None:
        self.r.hset(f"st:inst:{s.scope_id}", mapping=s.model_dump())
    def get_state(self, scope_id: str) -> InstanceState | None:
        h = self.r.hgetall(f"st:inst:{scope_id}")
        return InstanceState(**{**h, "retries": int(h.get("retries", 0))}) if h else None
    # --- dedup (SR-STATE-02, INV-3) ---
    def dedup_check_and_add(self, tree_id: str, tnode_id: str, sig: str) -> bool:
        """SADD의 원자성으로 gate. 반환 True=신규(디스패치 진행), False=중복(생략)."""
        added = self.r.sadd(f"st:dedup:{tree_id}", f"{tnode_id}|{sig}")
        return bool(added)
    # --- compromise context (DM-4) — 원자적 read-modify-write ---
    def get_ctx(self, path_id: str) -> CompromiseContext | None:
        v = self.r.get(f"st:ctx:{path_id}")
        return CompromiseContext.model_validate_json(v) if v else None
    def add_foothold(self, path_id: str, foothold) -> None:
        """WATCH/MULTI로 경합 없이 foothold append. 없으면 생성(FR-SM-09)."""
        key = f"st:ctx:{path_id}"
        with self.r.pipeline() as pipe:
            while True:
                try:
                    pipe.watch(key)
                    cur = pipe.get(key)
                    ctx = CompromiseContext.model_validate_json(cur) if cur else \
                          CompromiseContext(path_id=path_id, compromised=[])
                    if not any(f.tnode_id == foothold.tnode_id for f in ctx.compromised):
                        ctx.compromised.append(foothold)          # node_seq prefix 순서 유지
                    pipe.multi(); pipe.set(key, ctx.model_dump_json()); pipe.execute(); return
                except redis.WatchError:
                    continue
    # --- 트리 상방 성공 전파용 ---
    def mark_success(self, tree_id: str, tnode_id: str) -> None:
        self.r.sadd(f"st:success:{tree_id}", tnode_id)
    def successes(self, tree_id: str) -> set[str]:
        return self.r.smembers(f"st:success:{tree_id}")


def exploit_signature(attack_class: str, *, stacktrace: str="", sanitizer: str="", effect: str="",
                      attack_seq=None, affected_params=None) -> str:
    """crash: 정규화 스택트레이스 해시 ⊕ sanitizer/effect.
       logic: (공격 시퀀스·영향 파라미터/상태) 정규화 해시 ⊕ effect."""
    import hashlib, re
    if attack_class == "crash":
        norm = re.sub(r"0x[0-9a-f]+|\d+", "N", (stacktrace or "").lower())
        base = f"{hashlib.sha256(norm.encode()).hexdigest()[:16]}|{sanitizer}|{effect}"
    else:
        payload = json.dumps({"seq": attack_seq or [], "params": sorted(affected_params or [])}, sort_keys=True)
        base = f"{hashlib.sha256(payload.encode()).hexdigest()[:16]}|{effect}"
    return base
