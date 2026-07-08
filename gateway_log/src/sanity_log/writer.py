"""
7. Log — 라이터(기록기).

append-only JSONL(한 줄에 사건 하나)로 남긴다.
핵심 규칙(설계 §3.3):
  - 여러 프로세스가 한 파일에 동시에 쓰면 글씨가 뭉개진다(특히 Windows).
    → 그래서 "프로세스마다 자기 파일"에 쓴다. 조회는 나중에 trace_id로 합친다.
  - 기록 전 마스킹(비밀 가리기).
  - 한 줄 쓰고 바로 flush → 프로세스가 갑자기 죽어도 그전 기록은 남는다.
"""
from __future__ import annotations

import json
import os
import threading
import uuid
from pathlib import Path
from typing import Any

from .schema import Event, LLMCallRecord
from .mask import redact_dict


class LogWriter:
    def __init__(self, component: str, log_dir: str | None = None):
        self.component = component
        base = Path(log_dir or os.getenv("SANITY_LOG_DIR", "./logs"))
        base.mkdir(parents=True, exist_ok=True)
        # 파일명에 프로세스ID+랜덤을 붙여 "내 파일"을 확보 → 동시쓰기 충돌 없음
        instance = f"{os.getpid()}-{uuid.uuid4().hex[:8]}"
        self.path = base / f"comp{component}.{instance}.jsonl"
        self._lock = threading.Lock()            # 같은 프로세스 안 여러 스레드 보호
        self._fh = self.path.open("a", encoding="utf-8")

    # --- 낮은 수준: 사건 하나 기록 ---
    def write(self, event: Event) -> None:
        record = redact_dict(event.to_dict())    # 마스킹 후
        line = json.dumps(record, ensure_ascii=False)
        with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()                     # 바로 디스크로

    # --- 편의 함수들 ---
    def event(self, event_type: str, trace_id: str, component: str | None = None, **kw: Any) -> None:
        """일반 사건 기록. component를 주면 라이터 기본값 대신 그 값(예: 서브컴포넌트 "3.1")을 쓴다.
        state/scope_id/payload_ref 등은 kw로 전달되며 Event가 받는 필드가 아니면 extra로 흡수된다."""
        known = {"scope_id", "state", "payload_ref"}
        fields = {k: kw.pop(k) for k in list(kw) if k in known}
        self.write(Event(component=component or self.component, event_type=event_type,
                         trace_id=trace_id, extra=kw, **fields))

    def emit(self, envelope: dict[str, Any]) -> None:
        """DM-8 EventEnvelope(dict, 상태 버스에서 온 것)를 그대로 로그에 남긴다(상관용).
        component/event_type/trace_id 를 뽑고 나머지는 extra로 흡수한다."""
        e = dict(envelope)
        self.write(Event(
            component=str(e.pop("component", self.component)),
            event_type=str(e.pop("event_type", "status")),
            trace_id=str(e.pop("trace_id", "")),
            scope_id=e.pop("scope_id", None), state=e.pop("state", None),
            payload_ref=e.pop("payload_ref", None),
            ts=e.pop("ts", None) or __import__("time").time(),
            extra={k: v for k, v in e.items() if v is not None},
        ))

    def llm_call(self, record: LLMCallRecord) -> None:
        self.write(record.to_event())

    def close(self) -> None:
        with self._lock:
            try:
                self._fh.flush()
                self._fh.close()
            except Exception:
                pass

    def __enter__(self) -> "LogWriter":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
