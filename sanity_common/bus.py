# sanity_common/bus.py
import json, os
from typing import Iterator
import redis

class Bus:
    def __init__(self, url: str | None = None):
        url = url or os.getenv("REDIS_URL_BUS", "redis://redis:6379/0")   # 동적 스폰 env 존중(§2)
        self.r = redis.Redis.from_url(url, decode_responses=True)
    def publish(self, stream: str, obj: dict, maxlen: int = 100_000) -> str:
        """XADD. obj는 {'json': <직렬화문자열>} 단일 필드로 저장(스키마 단순화)."""
        return self.r.xadd(stream, {"json": json.dumps(obj, ensure_ascii=False)}, maxlen=maxlen, approximate=True)
    def ensure_group(self, stream: str, group: str) -> None:
        try: self.r.xgroup_create(stream, group, id="0", mkstream=True)
        except redis.ResponseError as e:
            if "BUSYGROUP" not in str(e): raise
    def consume(self, stream: str, group: str, consumer: str,
                block_ms: int = 5000, count: int = 10) -> Iterator[tuple[str, dict]]:
        """(msg_id, obj) 무한 이터레이터. 호출측이 처리 후 ack(stream, group, msg_id)."""
        self.ensure_group(stream, group)
        while True:
            resp = self.r.xreadgroup(group, consumer, {stream: ">"}, count=count, block=block_ms)
            if not resp: continue
            for _s, msgs in resp:
                for msg_id, fields in msgs:
                    yield msg_id, json.loads(fields["json"])
    def ack(self, stream: str, group: str, msg_id: str) -> None:
        self.r.xack(stream, group, msg_id)
    def reclaim(self, stream: str, group: str, consumer: str, min_idle_ms: int = 60000):
        """재기동 시 미처리 메시지 회수(FR-SR-DEPLOY-02)."""
        return self.r.xautoclaim(stream, group, consumer, min_idle_time=min_idle_ms, start_id="0")
