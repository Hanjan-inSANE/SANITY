"""
7. Log — 마스킹.

로그에 비밀번호/키가 평문으로 남으면 안 된다(SR-SEC-03).
기록하기 전에 민감해 보이는 값을 <redacted>로 까맣게 지운다.
설계 근거: SANITY_6_7_설계명세 §3.8.
"""
from __future__ import annotations

import re
from typing import Any

# "key=...", "token: ...", "Bearer sk-..." 같은 패턴을 찾아 값 부분만 가린다.
_KV = re.compile(
    r"(?i)\b(api[_-]?key|secret|token|password|passwd|credential|authorization)\b"
    r"(\s*[:=]\s*|\s+)(\S+)"
)
# sk- 로 시작하는 흔한 API 키 형태도 직접 가린다.
_SK = re.compile(r"\bsk-[A-Za-z0-9_\-]{6,}\b")
# "Bearer <토큰>" 형태(sk- 가 아니어도) 토큰 전체를 가린다(B8 수정).
_BEARER = re.compile(r"(?i)\bBearer\s+\S+")

REDACTED = "<redacted>"


def redact_text(text: str | None) -> str:
    if not text:
        return ""
    # 순서 중요: 'Bearer <토큰>'을 먼저 가려야 한다. 안 그러면 아래 _KV가 "Authorization: Bearer"의
    # 값으로 "Bearer"만 먹고 실제 토큰을 남긴다(목 테스트가 잡아낸 버그).
    t = _BEARER.sub(f"Bearer {REDACTED}", text)
    t = _KV.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", t)
    t = _SK.sub(REDACTED, t)
    return t


def redact_dict(d: dict[str, Any]) -> dict[str, Any]:
    """딕셔너리의 문자열 값들을 재귀적으로 마스킹."""
    out: dict[str, Any] = {}
    for k, v in d.items():
        if isinstance(v, str):
            out[k] = redact_text(v)
        elif isinstance(v, dict):
            out[k] = redact_dict(v)
        else:
            out[k] = v
    return out
