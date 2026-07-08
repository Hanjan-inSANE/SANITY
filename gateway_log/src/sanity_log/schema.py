"""
7. Log — 데이터 계약(스키마).

로그 한 줄이 어떤 모양인지 정의한다.
설계 근거: SANITY_6_7_설계명세 §3.2(공통 봉투) / 부록 C(LLM 호출 레코드).

두 가지가 있다:
  1) Event        — 모든 사건의 공통 봉투(무슨 일이 언제 어디서)
  2) LLMCallRecord — AI를 한 번 부른 기록(토큰/비용 등 추가 정보)
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Any, Optional


# 공통 봉투가 가질 수 있는 사건 종류
EVENT_TYPES = ("llm_call", "status", "tool_call", "artifact", "error")
# 상태값
STATES = ("PENDING", "RUNNING", "SUCCESS", "FAIL")


@dataclass
class Event:
    """모든 사건의 공통 봉투. component=어느 컴포넌트(0~9)에서 났는지."""
    component: str                       # "0"~"9"
    event_type: str                      # EVENT_TYPES 중 하나
    trace_id: str                        # 작업 추적번호(택배 송장번호)
    scope_id: Optional[str] = None       # 세부 인스턴스(예: tree3.node7.attacker)
    state: Optional[str] = None          # STATES 중 하나
    payload_ref: Optional[str] = None    # 큰 데이터는 여기에 "위치"만 (artifact://...)
    ts: float = field(default_factory=time.time)
    extra: dict[str, Any] = field(default_factory=dict)  # 그 밖의 자유 필드

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        extra = d.pop("extra") or {}
        d.update(extra)                  # extra 안의 키들을 최상위로 펼침
        return {k: v for k, v in d.items() if v is not None}


@dataclass
class LLMCallRecord:
    """AI를 한 번 부른 기록. 6.4(게이트웨이 콜백/클라이언트)가 채운다.
    필드명은 본선 OTEL(gen_ai.*)과 정렬해 둔다(승격 대비).
    비용(cost_usd)은 우리가 계산하지 않고 LiteLLM이 준 값을 그대로 쓴다(중복계산 금지)."""
    component: str
    trace_id: str
    scope_id: Optional[str]
    model: str                           # 별칭(sane-sonnet 등) 또는 실제 서빙 모델
    provider: str = ""                   # anthropic / openai / ollama
    state: str = "SUCCESS"               # SUCCESS | FAIL
    attempt: int = 1                     # 몇 번째 시도인지
    prompt_tokens: int = 0               # 입력 토큰 (~gen_ai.usage.input_tokens)
    completion_tokens: int = 0           # 출력 토큰 (~output_tokens)
    cache_read_tokens: int = 0           # 캐시로 아낀 토큰 (관측용, 비용계산엔 안 씀)
    cache_creation_tokens: int = 0
    cost_usd: Optional[float] = None     # LiteLLM이 준 금액(권위). 없으면 None
    latency_ms: int = 0
    stop_reason: str = ""
    request_ref: Optional[str] = None    # 프롬프트 본문 위치(마스킹 후)
    response_ref: Optional[str] = None
    gen_ai_id: Optional[str] = None      # AI 응답 ID
    ts: float = field(default_factory=time.time)

    def to_event(self) -> Event:
        """LLM 기록을 공통 봉투(Event)로 감싼다 → 한 줄로 저장 가능."""
        payload = {k: v for k, v in asdict(self).items()
                   if k not in ("component", "trace_id", "scope_id", "state", "ts")}
        return Event(
            component=self.component,
            event_type="llm_call",
            trace_id=self.trace_id,
            scope_id=self.scope_id,
            state=self.state,
            ts=self.ts,
            extra=payload,
        )
