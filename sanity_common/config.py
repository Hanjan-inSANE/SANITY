# sanity_common/config.py
import os
from pydantic import BaseModel
class SanityConfig(BaseModel):
    redis_url_bus: str = "redis://redis:6379/0"
    redis_url_state: str = "redis://redis:6379/1"
    gateway_url: str = "http://gateway:4000"      # = LITELLM_API_BASE
    gateway_model: str = "sane-sonnet"            # 기본 모델 별칭(gateway_log config.yaml, FR-GW-03)
    # 가상키 허용 모델 = 기본 + 폴백 티어(client.DEFAULT_FALLBACKS와 정합). 폴백이 auth-reject되지 않게 전부 포함.
    gateway_models: list[str] = ["sane-sonnet","sane-opus","sane-haiku","sane-oai-fallback","sane-local"]
    toolset_root: str = "/opt/Toolset"            # Toolset stdio 서버 PYTHONPATH(§8.5). HTTP 아님.
    rag_url: str = "http://100.77.84.85:9843"     # DB(5) Attack-RAG (threat_modeler attack_rag 기본과 정합)
    max_retry: int = 8                            # FR-SR-BUDGET-02 (config 노출, 정당한 이유)
    budget_split: str = "equal"                   # FR-SM-04 균등(가중 오버라이드 가능)
    total_token_budget: int = 5_000_000           # 예선 총량 미공개 → config
    token_price_per_1k: float = 0.003             # 토큰→USD 사상(Gateway max_budget 강제, FR-GW-02)
    default_rpm: int = 60; default_tpm: int = 200_000
    default_wall_clock_s: int = 1800              # per-agent 시한(Allocator 강제, FR-SR-BUDGET-01)
    dag_mode: bool = False                        # §4 tnode_id 모드
    scoring_adapter: str = "local"                # FR-SM-11 예선 로컬 sink / 본선 어댑터 교체

# env 이름 → SanityConfig 필드. 명시 이름을 우선 존중하고, 없으면 대문자 필드명으로 폴백한다.
_ENV_ALIASES: dict[str, str] = {
    "redis_url_bus": "REDIS_URL_BUS",
    "redis_url_state": "REDIS_URL_STATE",
    "gateway_url": "LITELLM_API_BASE",
    "gateway_model": "SANITY_GATEWAY_MODEL",
    "toolset_root": "TOOLSET_ROOT",
    "rag_url": "SANITY_RAG_URL",
}

def load_config() -> SanityConfig:                # env override 지원
    """SanityConfig 기본값을 환경변수로 override 한다.
    각 필드 f에 대해 _ENV_ALIASES[f] 또는 SANITY_<F>(대문자) 환경변수가 있으면 필드 타입으로 파싱해 적용한다."""
    defaults = SanityConfig()
    overrides: dict = {}
    for field, info in SanityConfig.model_fields.items():
        env_names = []
        if field in _ENV_ALIASES:
            env_names.append(_ENV_ALIASES[field])
        env_names.append("SANITY_" + field.upper())
        raw = next((os.environ[n] for n in env_names if os.environ.get(n) is not None), None)
        if raw is None:
            continue
        cur = getattr(defaults, field)
        if isinstance(cur, bool):
            overrides[field] = raw.strip().lower() in ("1", "true", "yes", "on")
        elif isinstance(cur, int):
            overrides[field] = int(raw)
        elif isinstance(cur, float):
            overrides[field] = float(raw)
        elif isinstance(cur, list):
            overrides[field] = [x for x in (s.strip() for s in raw.split(",")) if x]
        else:
            overrides[field] = raw
    return SanityConfig(**overrides)
