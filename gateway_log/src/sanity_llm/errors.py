"""
6. Gateway 클라이언트 — 에러 분류.

AI 호출이 실패했을 때 "어떤 실패냐"에 따라 대응이 다르다(설계 §2.7).
  - RATE_LIMIT   : 너무 빨리 불렀다 → 잠깐 쉬고 재시도 (프록시가 이미 함)
  - CONTEXT      : 입력이 너무 길다 → 재시도/폴백 하지 말고 입력을 줄여야 함
  - CONTENT      : 콘텐츠 필터에 걸림 → 폴백 하지 말고 상위 보고
  - TRANSIENT    : 일시적 오류 → 다른 모델로 폴백 시도 가능
  - AUTH/OTHER   : 키 문제 등 → 폴백 무의미, 즉시 실패
"""
from __future__ import annotations

RATE_LIMIT = "rate_limit"
CONTEXT = "context_length"
CONTENT = "content_filter"
TRANSIENT = "transient"
AUTH = "auth"
OTHER = "other"

# 폴백(다른 모델로 재시도)을 해도 되는 종류.
# RATE_LIMIT 포함 이유(B3 수정): 프록시가 이미 자체 재시도(num_retries)를 다 쓰고도 429가 오면,
# 그건 그 모델/프로바이더가 포화됐다는 뜻 → 다른 모델로 폴백하는 게 맞다.
# CONTEXT(입력 너무 김)·CONTENT(필터)·AUTH(키 문제)는 폴백해도 똑같이 실패하므로 제외.
FALLBACKABLE = {TRANSIENT, RATE_LIMIT}


def classify(exc: Exception) -> str:
    """openai SDK 예외를 우리 분류로 변환. (SDK 미설치 환경도 안전하게 처리)"""
    name = type(exc).__name__
    msg = str(exc).lower()

    if name in ("RateLimitError",) or "rate limit" in msg or "429" in msg:
        return RATE_LIMIT
    if "context length" in msg or "context_length" in msg or "maximum context" in msg:
        return CONTEXT
    if "content filter" in msg or "content_filter" in msg or "responsible ai" in msg:
        return CONTENT
    if name in ("AuthenticationError", "PermissionDeniedError") or "invalid api key" in msg:
        return AUTH
    if name in ("APITimeoutError", "APIConnectionError", "InternalServerError") or "timeout" in msg:
        return TRANSIENT
    return OTHER
