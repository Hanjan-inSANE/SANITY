"""
6. Gateway 클라이언트 — 에이전트가 AI를 부를 때 쓰는 유일한 창구 라이브러리.

핵심:
  - 에이전트는 진짜 프로바이더 키를 모른다. 창구 주소(LITELLM_API_BASE)와
    선불카드(LITELLM_API_KEY, 가상키)만 안다. → 그걸로 프록시에 요청한다.
  - OpenAI 호환 방식이라 표준 openai SDK를 그대로 쓴다(프록시가 실제 Claude로 라우팅).
  - 호출할 때마다 7번 Log에 자동 기록한다.
  - 하드 실패 시 다음 모델로 폴백한다(설계 §2.7 L3).
  - JSON을 받아야 하면 1회 자가수리한다(threat_modeler call_and_parse 이식, §2.7 L2).

로깅 방식(중요): P0에서는 "클라이언트 측"에서 로그를 남긴다. 모든 에이전트가 이 GatewayClient를
유일 창구로 쓰므로 단일 원천이 유지된다. 단, (a) GatewayClient를 안 거치는 호출은 로깅되지 않고
(b) 프록시 내부 재시도(L1)는 시도별로 보이지 않는다. 본선(P1)에는 프록시 `callbacks:["otel"]`로
전환해 이 한계를 없앤다(설계 §3.4).

설치 필요:  pip install openai requests
설계 근거: SANITY_6_7_설계명세 §2.9, §3.4
"""
from __future__ import annotations

import json
import re
import os
import time
from dataclasses import dataclass
from typing import Any, Optional

from . import errors

# 7번 로그 (없어도 동작하도록 안전하게 import)
try:
    from sanity_log import LogWriter, LLMCallRecord
except Exception:  # 로그 라이브러리 경로가 아직 안 잡혔을 때도 죽지 않게
    LogWriter = None       # type: ignore
    LLMCallRecord = None   # type: ignore


# 기본 폴백 체인 (§2.7). grounding(sane-ground)은 폴백 없음 → complete()에서 별도 처리.
DEFAULT_FALLBACKS = ["sane-sonnet", "sane-opus", "sane-haiku", "sane-local"]


@dataclass
class LLMResult:
    text: str
    model: str
    provider: str
    prompt_tokens: int
    completion_tokens: int
    cache_read_tokens: int
    cache_creation_tokens: int
    cost_usd: Optional[float]
    latency_ms: int
    stop_reason: str
    fallback_used: bool


class GatewayClient:
    def __init__(
        self,
        component: str,                       # 이 에이전트가 몇 번 컴포넌트인지 ("1"/"3"/"4")
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,        # 가상키
        log: Optional["LogWriter"] = None,    # 7번 로그 라이터(없으면 안 남김)
    ):
        from openai import OpenAI            # 여기서 import → openai 미설치 환경에서도 모듈 로드는 됨
        self.component = component
        self._client = OpenAI(
            base_url=(base_url or os.environ["LITELLM_API_BASE"]).rstrip("/"),
            api_key=api_key or os.environ["LITELLM_API_KEY"],
        )
        self.log = log

    # ---------------- 한 번 호출 ----------------
    def complete(
        self,
        model: str,                           # 별칭: sane-sonnet 등
        user: str = "",
        system: Optional[str] = None,
        trace_id: str = "",
        scope_id: Optional[str] = None,
        max_tokens: int = 4096,
        fallbacks: Optional[list[str]] = None,
        extra_body: Optional[dict[str, Any]] = None,
        messages: Optional[list[dict[str, str]]] = None,   # 대화 직접 지정(자가수리용)
    ) -> LLMResult:
        """모델을 부르고 결과를 돌려준다. 하드 실패 시 폴백. 매(모델) 시도 로그.
        messages를 주면 그걸 그대로 쓰고, 아니면 system/user로 만든다."""
        if messages is None:
            messages = []
            if system:
                messages.append({"role": "system", "content": system})
            messages.append({"role": "user", "content": user})

        # 폴백 미지정 시 기본 체인 사용(§2.7 L3). 명시적으로 fallbacks=[] 를 주면 폴백 끔.
        fb = DEFAULT_FALLBACKS if fallbacks is None else fallbacks
        chain = [model] + [m for m in fb if m != model]
        # grounding 전용 모델은 폴백 금지(§2.4/§2.7)
        if model == "sane-ground":
            chain = [model]

        last_exc: Optional[Exception] = None
        for attempt, mdl in enumerate(chain, start=1):
            # 프록시에 trace_id/scope_id 를 metadata 로 전달 → 로그 상관에 사용
            body: dict[str, Any] = {"metadata": {"trace_id": trace_id, "scope_id": scope_id or ""}}
            if extra_body:
                body.update(extra_body)

            t0 = time.time()
            try:
                raw = self._client.chat.completions.with_raw_response.create(
                    model=mdl, messages=messages, max_tokens=max_tokens, extra_body=body,
                )
                resp = raw.parse()
                latency = int((time.time() - t0) * 1000)
                res = self._to_result(mdl, resp, raw.headers, latency,
                                      fallback_used=(mdl != model))
                self._log(res, trace_id, scope_id, attempt, state="SUCCESS")
                return res
            except Exception as exc:              # 실패
                latency = int((time.time() - t0) * 1000)
                kind = errors.classify(exc)
                self._log_fail(mdl, trace_id, scope_id, attempt, latency, kind)
                last_exc = exc
                # 폴백해도 되는 실패만 다음 모델로. 아니면 즉시 중단.
                if kind not in errors.FALLBACKABLE:
                    break
        raise RuntimeError(f"LLM 호출 실패(all fallbacks): {last_exc}") from last_exc

    # ---------------- JSON 받기(1회 자가수리) ----------------
    def complete_json(self, model: str, user: str, system: Optional[str] = None,
                      **kw: Any) -> Any:
        """엄격한 JSON 응답을 파싱. 실패하면 원래 대화를 이어 1회 고쳐 달라 요청(§2.7 L2)."""
        res = self.complete(model, user=user, system=system, **kw)
        try:
            return _extract_json(res.text)
        except ValueError as first:
            # 원래 질문 + 잘못된 응답 + 수리요청을 '대화로 이어붙여' 맥락을 보존한다(B1 수정).
            repair_msgs: list[dict[str, str]] = []
            if system:
                repair_msgs.append({"role": "system", "content": system})
            repair_msgs.append({"role": "user", "content": user})
            repair_msgs.append({"role": "assistant", "content": res.text or "(빈 응답)"})
            repair_msgs.append({"role": "user", "content": (
                f"방금 응답이 올바른 JSON이 아니었다({first}). "
                "코드블록·설명·주석 없이 '오직' 유효한 JSON만 다시 출력하라.")})
            kw2 = {k: v for k, v in kw.items() if k not in ("messages", "system", "user")}
            res2 = self.complete(model, messages=repair_msgs, **kw2)
            return _extract_json(res2.text)

    # ---------------- 내부 도우미 ----------------
    def _to_result(self, requested_model, resp, headers, latency, fallback_used) -> LLMResult:
        choice = resp.choices[0]
        usage = getattr(resp, "usage", None)
        pt = getattr(usage, "prompt_tokens", 0) or 0
        ct = getattr(usage, "completion_tokens", 0) or 0
        # 캐시 토큰(관측용). 프로바이더/버전마다 위치가 달라 두 방식을 다 시도(B2 수정).
        cache_read = cache_create = 0
        if usage is not None:
            details = getattr(usage, "prompt_tokens_details", None)
            if details is not None:
                cache_read = getattr(details, "cached_tokens", 0) or 0
            cache_read = cache_read or (getattr(usage, "cache_read_input_tokens", 0) or 0)
            cache_create = getattr(usage, "cache_creation_input_tokens", 0) or 0
        # 비용: LiteLLM이 응답 헤더에 실어주는 값을 쓴다(우리가 재계산 X, §2.8/§3.7)
        cost = None
        try:
            hv = headers.get("x-litellm-response-cost")
            cost = float(hv) if hv is not None else None
        except Exception:
            cost = None
        served = getattr(resp, "model", requested_model) or requested_model
        return LLMResult(
            text=choice.message.content or "",
            model=served,
            provider=_infer_provider(served),   # 빈 문자열 방지(B7 수정)
            prompt_tokens=pt, completion_tokens=ct,
            cache_read_tokens=cache_read, cache_creation_tokens=cache_create,
            cost_usd=cost, latency_ms=latency,
            stop_reason=getattr(choice, "finish_reason", "") or "",
            fallback_used=fallback_used,
        )

    def _log(self, res: LLMResult, trace_id, scope_id, attempt, state):
        if not (self.log and LLMCallRecord):
            return
        self.log.llm_call(LLMCallRecord(
            component=self.component, trace_id=trace_id, scope_id=scope_id,
            model=res.model, provider=res.provider, state=state, attempt=attempt,
            prompt_tokens=res.prompt_tokens, completion_tokens=res.completion_tokens,
            cache_read_tokens=res.cache_read_tokens,
            cache_creation_tokens=res.cache_creation_tokens,
            cost_usd=res.cost_usd, latency_ms=res.latency_ms, stop_reason=res.stop_reason,
        ))

    def _log_fail(self, model, trace_id, scope_id, attempt, latency, kind):
        if not (self.log and LLMCallRecord):
            return
        self.log.llm_call(LLMCallRecord(
            component=self.component, trace_id=trace_id, scope_id=scope_id,
            model=model, state="FAIL", attempt=attempt, latency_ms=latency,
            stop_reason=kind,
        ))


def _infer_provider(served: str) -> str:
    """서빙 모델명에서 프로바이더를 추정(B7). '/'가 있으면 앞부분, 없으면 이름으로 판별."""
    if "/" in served:
        return served.split("/")[0]
    s = served.lower()
    if "claude" in s:
        return "anthropic"
    if s.startswith(("gpt", "o1", "o3", "o4")) or "gpt" in s:
        return "openai"
    if any(x in s for x in ("qwen", "llama", "mistral", "gemma")):
        return "ollama"
    return ""


# --- threat_modeler 의 JSON 추출 로직 이식(가벼운 버전) ---
def _extract_json(text: str) -> Any:
    t = (text or "").strip().replace("```json", "").replace("```JSON", "").replace("```", "")
    starts = [i for i in (t.find("{"), t.find("[")) if i >= 0]
    if not starts:
        raise ValueError("응답에 JSON이 없음")
    s = min(starts)
    e = max(t.rfind("}"), t.rfind("]"))
    if e > s:
        t = t[s:e + 1]
    for cand in (t, re.sub(r",(\s*[}\]])", r"\1", t)):   # 뒤따라오는 쉼표 제거 후 재시도