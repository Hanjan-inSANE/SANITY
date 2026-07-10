"""
LLM provider wrapper for the networked stages.

Anthropic keeps the original SDK path. Ollama uses its local REST API
directly via the standard library, so local/free models do not add a
Python dependency.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .models import (
    ANTHROPIC,
    OPENAI,
    OLLAMA,
    OLLAMA_CLOUD,
    DEFAULT_OLLAMA_BASE_URL,
    DEFAULT_OPENAI_BASE_URL,
    normalize_provider,
)


class LLMError(RuntimeError):
    pass


@dataclass
class TextResponse:
    text: str
    stop_reason: str = ""


def _anthropic_client(api_key: str):
    try:
        import anthropic  # noqa: WPS433 (import inside function is deliberate)
    except ImportError as exc:  # pragma: no cover - env-dependent
        raise LLMError(
            "The 'anthropic' package is required for Anthropic models. "
            "Install it with:  pip install anthropic"
        ) from exc
    if not api_key:
        raise LLMError("API key required for Anthropic (pass --api-key or set ANTHROPIC_API_KEY)")
    return anthropic.Anthropic(api_key=api_key)


def _ollama_chat_url(base_url: Optional[str]) -> str:
    base = (base_url or DEFAULT_OLLAMA_BASE_URL).strip().rstrip("/")
    if base.endswith("/api"):
        return base + "/chat"
    return base + "/api/chat"


def call_claude(
    api_key: str,
    model: str,
    messages: List[Dict[str, Any]],
    system: Optional[str] = None,
    max_tokens: int = 4096,
) -> Any:
    """Single Anthropic Messages API call. Returns the SDK response object."""
    client = _anthropic_client(api_key)
    kwargs: Dict[str, Any] = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": messages,
    }
    if system:
        kwargs["system"] = system
    try:
        return client.messages.create(**kwargs)
    except Exception as exc:  # surface a clean error to the pipeline
        raise LLMError(f"Anthropic API call failed: {exc}") from exc


def call_ollama(
    api_key: str,
    model: str,
    messages: List[Dict[str, Any]],
    system: Optional[str] = None,
    base_url: Optional[str] = None,
    max_tokens: int = 4096,
) -> TextResponse:
    """Single Ollama /api/chat call with streaming disabled."""
    chat_messages: List[Dict[str, str]] = []
    if system:
        chat_messages.append({"role": "system", "content": system})
    for m in messages:
        role = str(m.get("role", "user"))
        if role not in {"system", "user", "assistant"}:
            role = "user"
        chat_messages.append({"role": role, "content": str(m.get("content", ""))})

    body: Dict[str, Any] = {
        "model": model,
        "messages": chat_messages,
        "stream": False,
        "options": {"num_predict": max_tokens},
    }
    data = json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = urllib.request.Request(_ollama_chat_url(base_url), data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=600) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        msg = exc.read().decode("utf-8", errors="replace")
        raise LLMError(f"Ollama API call failed: HTTP {exc.code}: {msg}") from exc
    except urllib.error.URLError as exc:
        raise LLMError(
            "Ollama API call failed. Is Ollama running? "
            f"Expected {(_ollama_chat_url(base_url))}. Details: {exc}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise LLMError(f"Ollama response was not valid JSON: {exc}") from exc

    message = payload.get("message") or {}
    content = message.get("content", "")
    stop = "stop" if payload.get("done") else str(payload.get("done_reason", ""))
    return TextResponse(text=str(content), stop_reason=stop)


def _openai_chat_url(base_url: Optional[str]) -> str:
    base = (base_url or DEFAULT_OPENAI_BASE_URL).strip().rstrip("/")
    if not base:
        raise LLMError(
            "The OpenAI-compatible provider needs a base URL "
            "(e.g. https://openrouter.ai/api/v1)."
        )
    if base.endswith("/chat/completions"):
        return base
    return base + "/chat/completions"


def call_openai(
    api_key: str,
    model: str,
    messages: List[Dict[str, Any]],
    system: Optional[str] = None,
    base_url: Optional[str] = None,
    max_tokens: int = 4096,
) -> TextResponse:
    """Single OpenAI-compatible /chat/completions call (streaming disabled).

    Works with any hosted service that speaks the OpenAI chat schema —
    OpenRouter, Groq, Together, Fireworks, DeepInfra, a local vLLM/LM Studio
    server, etc. The caller supplies the base URL, API key, and model id.
    """
    if not api_key:
        raise LLMError("API key required for the OpenAI-compatible provider")
    chat_messages: List[Dict[str, str]] = []
    if system:
        chat_messages.append({"role": "system", "content": system})
    for m in messages:
        role = str(m.get("role", "user"))
        if role not in {"system", "user", "assistant"}:
            role = "user"
        chat_messages.append({"role": role, "content": str(m.get("content", ""))})

    body: Dict[str, Any] = {
        "model": model,
        "messages": chat_messages,
        "max_tokens": max_tokens,
        "stream": False,
    }
    data = json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
    url = _openai_chat_url(base_url)
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=600) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        msg = exc.read().decode("utf-8", errors="replace")
        raise LLMError(f"OpenAI-compatible API call failed: HTTP {exc.code}: {msg}") from exc
    except urllib.error.URLError as exc:
        raise LLMError(f"OpenAI-compatible API call failed (endpoint {url}): {exc}") from exc
    except json.JSONDecodeError as exc:
        raise LLMError(f"OpenAI-compatible response was not valid JSON: {exc}") from exc

    choices = payload.get("choices") or []
    message = (choices[0].get("message") or {}) if choices else {}
    content = message.get("content", "")
    finish = choices[0].get("finish_reason", "") if choices else ""
    stop = "max_tokens" if finish == "length" else str(finish or "")
    return TextResponse(text=str(content or ""), stop_reason=stop)


def call_model(
    api_key: str,
    provider: str,
    model: str,
    messages: List[Dict[str, Any]],
    system: Optional[str] = None,
    max_tokens: int = 4096,
    base_url: Optional[str] = None,
) -> Any:
    """Dispatch a chat request to the selected provider."""
    p = normalize_provider(provider)
    if p == ANTHROPIC:
        return call_claude(api_key, model, messages, system=system,
                           max_tokens=max_tokens)
    if p == OPENAI:
        return call_openai(api_key, model, messages, system=system,
                           base_url=base_url, max_tokens=max_tokens)
    if p in (OLLAMA, OLLAMA_CLOUD):
        # Local Ollama and hosted Ollama Cloud share the /api/chat schema; the
        # only difference is the base URL and that Cloud gates on an API key
        # (sent as a bearer token).
        return call_ollama(api_key, model, messages, system=system,
                           base_url=base_url, max_tokens=max_tokens)
    raise LLMError(f"Unsupported LLM provider: {provider}")


def text_of(response: Any) -> str:
    """Concatenate text from either Anthropic SDK responses or TextResponse."""
    if isinstance(response, TextResponse):
        return response.text
    parts: List[str] = []
    for block in getattr(response, "content", []) or []:
        if getattr(block, "type", None) == "text":
            parts.append(getattr(block, "text", ""))
    return "\n".join(parts)


def _strip_trailing_commas(t: str) -> str:
    """Remove ``,}`` / ``,]`` sequences (a common LLM JSON slip)."""
    return re.sub(r",(\s*[}\]])", r"\1", t)


def _balanced_json_slices(text: str) -> List[str]:
    """Return balanced top-level JSON object/array slices found in text."""
    out: List[str] = []
    pairs = {"{": "}", "[": "]"}
    for start, ch in enumerate(text):
        if ch not in pairs:
            continue
        stack = [pairs[ch]]
        in_string = False
        escaped = False
        for pos in range(start + 1, len(text)):
            cur = text[pos]
            if in_string:
                if escaped:
                    escaped = False
                elif cur == "\\":
                    escaped = True
                elif cur == '"':
                    in_string = False
                continue
            if cur == '"':
                in_string = True
            elif cur in pairs:
                stack.append(pairs[cur])
            elif stack and cur == stack[-1]:
                stack.pop()
                if not stack:
                    out.append(text[start : pos + 1])
                    break
    return out


def extract_json(text: str) -> Any:
    """Extract and parse the first JSON object/array from model output."""
    t = (text or "").strip().replace("```json", "").replace("```JSON", "").replace("```", "")
    slices = _balanced_json_slices(t)
    if not slices:
        starts = [i for i in (t.find("{"), t.find("[")) if i >= 0]
        ends = [i for i in (t.rfind("}"), t.rfind("]")) if i >= 0]
        if starts and ends and max(ends) > min(starts):
            slices = [t[min(starts) : max(ends) + 1]]
    if not slices:
        raise LLMError("No JSON found in model output")
    first_err: Optional[json.JSONDecodeError] = None
    for item in slices:
        for candidate in (item, _strip_trailing_commas(item)):
            try:
                return json.loads(candidate)
            except json.JSONDecodeError as exc:
                if first_err is None:
                    first_err = exc
    raise LLMError(f"Model output was not valid JSON: {first_err}") from first_err


def call_and_parse(
    api_key: str,
    model: str,
    system: str,
    user: str,
    max_tokens: int = 4096,
    provider: str = ANTHROPIC,
    base_url: Optional[str] = None,
) -> Any:
    """Call a model and parse a STRICT-JSON response, with repair rounds."""
    messages: List[Dict[str, Any]] = [{"role": "user", "content": user}]
    last_err: Optional[LLMError] = None
    for attempt in range(4):
        resp = call_model(api_key, provider, model, messages, system=system,
                          max_tokens=max_tokens, base_url=base_url)
        raw = text_of(resp)
        try:
            return extract_json(raw)
        except LLMError as exc:
            last_err = exc
        if attempt >= 3:
            break
        truncated = getattr(resp, "stop_reason", None) == "max_tokens"
        hint = " Your previous reply was cut off; return a smaller but complete tree." if truncated else ""
        messages.append({"role": "assistant", "content": (raw or "(empty)")[:12000]})
        messages.append({"role": "user", "content": (
            f"That was not valid JSON ({last_err}).{hint} "
            "Regenerate the answer from the original task, not as an explanation. "
            "Reply with ONLY one complete, strictly valid JSON value: no prose, "
            "no code fences, no comments, no trailing commas. Escape all newline "
            "characters inside strings as \\n. If the structure is too large, "
            "make it smaller while preserving the root objective and concrete leaves."
        )})
    raise last_err or LLMError("Model output was not valid JSON")
