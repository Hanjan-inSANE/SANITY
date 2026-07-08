"""
Selectable model/provider catalog.

Anthropic remains the default provider so existing commands keep working.
Ollama entries are suggestions for local/free models; users may type any
locally installed Ollama model name and pass it through unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


ANTHROPIC = "anthropic"
OPENAI = "openai"          # OpenAI-compatible hosted API (OpenRouter, Groq, Together, ...)
OLLAMA = "ollama"          # local Ollama daemon
OLLAMA_CLOUD = "ollama-cloud"  # hosted Ollama Cloud (https://ollama.com) — API key
DEFAULT_PROVIDER = ANTHROPIC
DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434"
# Ollama Cloud speaks the same /api/chat schema as the local daemon, but is
# hosted and gated by an API key sent as a bearer token.
DEFAULT_OLLAMA_CLOUD_BASE_URL = "https://ollama.com"
# Default endpoint for the OpenAI-compatible provider (an aggregator that
# fronts many open models with one key). Users may point it at any
# /v1-style service via --base-url or the UI field.
DEFAULT_OPENAI_BASE_URL = "https://openrouter.ai/api/v1"
# Well-known OpenAI-compatible endpoints, surfaced as UI suggestions only.
OPENAI_PRESETS = {
    "OpenRouter": "https://openrouter.ai/api/v1",
    "Groq": "https://api.groq.com/openai/v1",
    "Together": "https://api.together.xyz/v1",
    "Fireworks": "https://api.fireworks.ai/inference/v1",
    "DeepInfra": "https://api.deepinfra.com/v1/openai",
    "Local (vLLM / LM Studio)": "http://localhost:8000/v1",
}


@dataclass(frozen=True)
class ModelInfo:
    id: str
    display_name: str
    status: str          # active | deprecated | local | hosted
    family: str          # sonnet | llama | qwen | mistral | gemma | custom
    provider: str = ANTHROPIC
    note: str = ""
    requires_api_key: bool = True


# Anthropic Sonnet-family models (newest first).
SONNET_MODELS: List[ModelInfo] = [
    ModelInfo("claude-sonnet-4-6", "Claude Sonnet 4.6", "active", "sonnet",
              ANTHROPIC, "best speed/intelligence balance", True),
    ModelInfo("claude-sonnet-4-5", "Claude Sonnet 4.5", "active", "sonnet",
              ANTHROPIC, "legacy but active", True),
    ModelInfo("claude-sonnet-4-0", "Claude Sonnet 4", "deprecated", "sonnet",
              ANTHROPIC, "deprecated; still callable", True),
]


# Hosted open models via an OpenAI-compatible API (no local install).
# Ids shown here are OpenRouter-style; other services use their own ids, so
# these are suggestions, not a whitelist — type any id your endpoint accepts.
OPENAI_MODELS: List[ModelInfo] = [
    ModelInfo("meta-llama/llama-3.1-70b-instruct", "Llama 3.1 70B Instruct", "hosted",
              "llama", OPENAI, "hosted via API key (OpenRouter id shown)", True),
    ModelInfo("meta-llama/llama-3.1-8b-instruct", "Llama 3.1 8B Instruct", "hosted",
              "llama", OPENAI, "smaller/cheaper hosted model", True),
    ModelInfo("qwen/qwen-2.5-72b-instruct", "Qwen2.5 72B Instruct", "hosted",
              "qwen", OPENAI, "strong hosted instruction model", True),
    ModelInfo("mistralai/mistral-7b-instruct", "Mistral 7B Instruct", "hosted",
              "mistral", OPENAI, "fast hosted baseline", True),
]


# Common Ollama local model names. These are suggestions, not a whitelist.
OLLAMA_MODELS: List[ModelInfo] = [
    ModelInfo("llama3.1:8b", "Llama 3.1 8B", "local", "llama", OLLAMA,
              "small general-purpose local model", False),
    ModelInfo("llama3.1:70b", "Llama 3.1 70B", "local", "llama", OLLAMA,
              "larger local model; needs substantial RAM/VRAM", False),
    ModelInfo("qwen2.5:7b-instruct", "Qwen2.5 7B Instruct", "local", "qwen",
              OLLAMA, "compact instruction-following model", False),
    ModelInfo("qwen2.5:14b-instruct", "Qwen2.5 14B Instruct", "local", "qwen",
              OLLAMA, "stronger local instruction-following model", False),
    ModelInfo("mistral:7b", "Mistral 7B", "local", "mistral", OLLAMA,
              "fast local baseline", False),
    ModelInfo("gemma2:9b", "Gemma 2 9B", "local", "gemma", OLLAMA,
              "local Google Gemma-family model", False),
]


# Hosted Ollama Cloud models (https://ollama.com), reached with an API key.
# These are common cloud tags; the field is suggestion-only, so any tag your
# account can pull — including newer Gemma releases — may be typed directly.
OLLAMA_CLOUD_MODELS: List[ModelInfo] = [
    ModelInfo("gemma3:27b", "Gemma 3 27B (cloud)", "hosted", "gemma", OLLAMA_CLOUD,
              "Google Gemma-family model via Ollama Cloud", True),
    ModelInfo("gemma3:12b", "Gemma 3 12B (cloud)", "hosted", "gemma", OLLAMA_CLOUD,
              "smaller/cheaper hosted Gemma", True),
    ModelInfo("gpt-oss:120b", "GPT-OSS 120B (cloud)", "hosted", "custom", OLLAMA_CLOUD,
              "large open model hosted on Ollama Cloud", True),
    ModelInfo("glm-4.6", "GLM-4.6 (cloud)", "hosted", "glm", OLLAMA_CLOUD,
              "Zhipu GLM via Ollama Cloud", True),
    ModelInfo("qwen3:32b", "Qwen3 32B (cloud)", "hosted", "qwen", OLLAMA_CLOUD,
              "strong hosted instruction model", True),
    ModelInfo("llama3.3:70b", "Llama 3.3 70B (cloud)", "hosted", "llama", OLLAMA_CLOUD,
              "hosted Llama 3.3", True),
    ModelInfo("deepseek-v3.1:671b", "DeepSeek-V3.1 (cloud)", "hosted", "custom", OLLAMA_CLOUD,
              "very large hosted MoE model", True),
]


MODELS: List[ModelInfo] = (
    list(SONNET_MODELS) + list(OPENAI_MODELS)
    + list(OLLAMA_CLOUD_MODELS) + list(OLLAMA_MODELS)
)

DEFAULT_MODEL: str = "claude-sonnet-4-6"
DEFAULTS = {
    ANTHROPIC: DEFAULT_MODEL,
    OPENAI: "meta-llama/llama-3.1-70b-instruct",
    OLLAMA_CLOUD: "gemma3:27b",
    OLLAMA: "llama3.1:8b",
}

# Per-provider default base URL (empty when the provider needs no endpoint).
DEFAULT_BASE_URLS = {
    ANTHROPIC: "",
    OPENAI: DEFAULT_OPENAI_BASE_URL,
    OLLAMA_CLOUD: DEFAULT_OLLAMA_CLOUD_BASE_URL,
    OLLAMA: DEFAULT_OLLAMA_BASE_URL,
}


def normalize_provider(provider: Optional[str]) -> str:
    p = (provider or DEFAULT_PROVIDER).strip().lower()
    if p in {ANTHROPIC, OPENAI, OLLAMA, OLLAMA_CLOUD}:
        return p
    raise ValueError(f"Unknown LLM provider: {provider!r}")


def is_known_model(model_id: str, provider: Optional[str] = None) -> bool:
    """True if ``model_id`` is in the catalog for the selected provider."""
    p = normalize_provider(provider) if provider else None
    return any(m.id == model_id and (p is None or m.provider == p) for m in MODELS)
