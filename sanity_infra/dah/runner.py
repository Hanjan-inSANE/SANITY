# sanity_infra/dah/runner.py — DAH 러너 (트리마다 즉시 발행 = 스트리밍)
import os, time
from threat_modeler.pipeline import run_pipeline, PipelineOptions
from threat_modeler.openxsampp import parse_openxsampp
from sanity_common.bus import Bus
from sanity_llm import issue_key

def ingest(openxsampp_path: str, cfg) -> None:
    model, config = parse_openxsampp(open(openxsampp_path, encoding="utf-8").read())
    tm_key = issue_key(key_alias=f"tm-{int(time.time())}", token_budget=cfg.total_token_budget,
                       token_price_per_1k=cfg.token_price_per_1k,
                       models=cfg.gateway_models, base_url=cfg.gateway_url)
    _use_rag = os.getenv("SANITY_USE_RAG", "1").strip().lower() in ("1","true","yes","on")
    opts = PipelineOptions(model=cfg.gateway_model, api_key=tm_key, provider="openai",
                           base_url=cfg.gateway_url, use_rag=_use_rag, rag_base_url=cfg.rag_url)
    bus = Bus(cfg.redis_url_bus)
    _pub = {"n": 0}
    def _on_tree(si, tr):
        bus.publish("sanity:tree:inbox", {"tree": tr.tree}); _pub["n"] += 1
        print(f"[publish] tree {_pub['n']} (scenario {si + 1}) -> SM 즉시 전달", flush=True)
    run_pipeline(model, opts, config=config, on_tree=_on_tree)   # 트리마다 즉시 발행
    print(f"[done] {_pub['n']} tree(s) 발행 완료.", flush=True)

if __name__ == "__main__":
    import sys
    from sanity_common.config import load_config
    path = sys.argv[1] if len(sys.argv) > 1 else "DVD.openxsampp.xml"
    ingest(path, load_config())
