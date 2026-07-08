# sanity_infra/dah/runner.py  (0. DAH Interface, 예선 로컬 러너 — FR-IF-0, §00-2.2)
from threat_modeler.pipeline import run_pipeline, PipelineOptions   # TM(1) 기존 구현(정본, 무수정)
from threat_modeler.openxsampp import parse_openxsampp              # -> (SystemModel, config)
from sanity_common.bus import Bus
from sanity_llm import issue_key                              # TM도 Gateway 경유(SR-STACK-02)

def ingest(openxsampp_path: str, cfg) -> None:
    model, config = parse_openxsampp(open(openxsampp_path, encoding="utf-8").read())
    tm_key = issue_key(key_alias="tm", token_budget=cfg.total_token_budget,      # TM용 가상키 1개
                       token_price_per_1k=cfg.token_price_per_1k,
                       models=cfg.gateway_models, base_url=cfg.gateway_url)
    # provider="openai"(OpenAI 호환) + base_url=Gateway + api_key=가상키 → TM LLM이 Gateway 경유
    opts = PipelineOptions(model=cfg.gateway_model, api_key=tm_key, provider="openai",
                           base_url=cfg.gateway_url, use_rag=True, rag_base_url=cfg.rag_url)
    bus = Bus(cfg.redis_url_bus)
    for tr in run_pipeline(model, opts, config=config):        # List[TreeResult]
        bus.publish("sanity:tree:inbox", {"tree": tr.tree})    # SM이 tree_id 부여·영속(§4)


if __name__ == "__main__":
    import sys
    from sanity_common.config import load_config
    # 사용법: python -m sanity_infra.dah.runner <openxsampp_path>
    path = sys.argv[1] if len(sys.argv) > 1 else "DVD.openxsampp.xml"
    ingest(path, load_config())
