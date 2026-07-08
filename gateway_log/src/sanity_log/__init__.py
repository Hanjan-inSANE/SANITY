"""7. Log — 로그 라이브러리 (append-only JSONL).

사용 예:
    from sanity_log import LogWriter, LLMCallRecord
    log = LogWriter(component="3")                 # 공격자 컴포넌트
    log.event("status", trace_id="t1", state="RUNNING", scope_id="tree3.node7.attacker")
"""
from .schema import Event, LLMCallRecord, EVENT_TYPES, STATES
from .writer import LogWriter
from .mask import redact_text, redact_dict

__all__ = [
    "Event", "LLMCallRecord", "LogWriter",
    "redact_text", "redact_dict", "EVENT_TYPES", "STATES",
]
