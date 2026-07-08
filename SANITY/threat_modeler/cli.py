"""Command-line entry point for Threat Modeler."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

from . import __version__
from .graph import build_engine_graph, scenario_paths, build_atoms
from .openxsampp import generate_openxsampp, parse_openxsampp
from .models import (
    ANTHROPIC,
    OPENAI,
    OLLAMA,
    OLLAMA_CLOUD,
    DEFAULT_MODEL,
    DEFAULT_PROVIDER,
    DEFAULTS,
    DEFAULT_BASE_URLS,
    DEFAULT_OLLAMA_BASE_URL,
    DEFAULT_OPENAI_BASE_URL,
    MODELS,
    is_known_model,
)
from .render import render_tree_svg, svg_to_png


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _load_config(path: Optional[str]) -> Dict[str, Dict[str, object]]:
    if not path:
        return {}
    return json.loads(_read(path))


def _load_model_config(args: argparse.Namespace):
    """Load an OpenXSAM++ .xml file into (SystemModel, config).

    A ``-c`` config JSON, if given, overrides the config embedded in the
    OpenXSAM++ document; otherwise the embedded config is used."""
    model, embedded = parse_openxsampp(_read(args.file))
    override = _load_config(getattr(args, "config", None))
    return model, (override or embedded)


def _log(msg: str, level: str = "info") -> None:
    colors = {"ok": "\033[32m", "warn": "\033[33m", "err": "\033[31m"}
    reset = "\033[0m"
    c = colors.get(level, "")
    stream = sys.stderr if level == "err" else sys.stdout
    print(f"{c}{msg}{reset}", file=stream)


def _api_key_for(args: argparse.Namespace) -> str:
    if args.api_key:
        return args.api_key
    env = {
        ANTHROPIC: "ANTHROPIC_API_KEY",
        OPENAI: "OPENAI_API_KEY",
        OLLAMA_CLOUD: "OLLAMA_API_KEY",
        OLLAMA: "OLLAMA_API_KEY",
    }.get(args.provider, "")
    return os.environ.get(env, "") if env else ""


def _base_url_for(args: argparse.Namespace) -> str:
    if args.base_url:
        return args.base_url
    env = {
        OPENAI: "OPENAI_BASE_URL",
        OLLAMA_CLOUD: "OLLAMA_CLOUD_BASE_URL",
        OLLAMA: "OLLAMA_BASE_URL",
    }.get(args.provider)
    if env and os.environ.get(env):
        return os.environ[env]
    return DEFAULT_BASE_URLS.get(args.provider, "")


def cmd_models(_args: argparse.Namespace) -> int:
    print(f"Selectable models (default: {DEFAULT_PROVIDER}/{DEFAULT_MODEL}):")
    for provider in (ANTHROPIC, OPENAI, OLLAMA_CLOUD, OLLAMA):
        print(f"\n[{provider}]")
        for m in [x for x in MODELS if x.provider == provider]:
            star = " *" if m.id == DEFAULT_MODEL else "  "
            key = "key" if m.requires_api_key else "no-key"
            print(f"{star} {m.id:<38} {m.display_name:<24} [{m.status}; {key}] {m.note}")
    print("\nAny other model id may be passed to --model as a custom override.")
    print(f"OpenAI-compatible default base URL: {DEFAULT_OPENAI_BASE_URL}")
    print(f"Ollama default base URL: {DEFAULT_OLLAMA_BASE_URL}")
    return 0


def cmd_openxsampp(args: argparse.Namespace) -> int:
    model, config = _load_model_config(args)
    print(generate_openxsampp(model, config))
    return 0


def cmd_paths(args: argparse.Namespace) -> int:
    model, config = _load_model_config(args)
    graph = build_engine_graph(model, config)
    paths = scenario_paths(
        graph, args.entry, args.endpoint, args.max_len, args.max_paths
    )
    print(f"{len(paths)} logical path(s):")
    for p in paths:
        print("  " + " -> ".join(graph.by_id[i].label for i in p))
    atom_set = build_atoms(graph, paths)
    print(f"{len(atom_set.atoms)} atom(s):")
    for a in atom_set.atoms:
        tail = f" -> {a.next_node.label}" if a.next_node else " (terminal)"
        print(f"  [{a.kind:<9}] {a.node.label}{tail}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    from .pipeline import run_pipeline, PipelineOptions

    model_id = DEFAULTS.get(args.provider, args.model) if args.model == DEFAULT_MODEL else args.model

    if not is_known_model(model_id, args.provider):
        _log(
            f"note: '{model_id}' is not a known {args.provider} catalog id; passing through.",
            "warn",
        )

    model, config = _load_model_config(args)
    graph = build_engine_graph(model, config)

    scenarios: Optional[List[Dict[str, Any]]] = None
    if args.scenarios:
        scenarios = json.loads(_read(args.scenarios))

    options = PipelineOptions(
        provider=args.provider,
        model=model_id,
        api_key=_api_key_for(args),
        base_url=_base_url_for(args),
        use_rag=not args.no_rag,
        rag_top_k=args.rag_top_k,
        rag_base_url=args.rag_url,
        max_path_len=args.max_len,
        max_paths=args.max_paths,
    )
    results = run_pipeline(
        graph, options, scenarios=scenarios,
        log=lambda m, l="info": _log("  " + m, l),
    )

    trees = [
        {
            "scenario": r.scenario,
            "tree": r.tree,
            "validationIssues": r.validation_issues,
        }
        for r in results
    ]
    if args.out_json:
        with open(args.out_json, "w", encoding="utf-8") as fh:
            json.dump(trees, fh, indent=2, ensure_ascii=False)
        _log(f"wrote {args.out_json}", "ok")
    else:
        print(json.dumps(trees, indent=2, ensure_ascii=False))

    if args.out_svg_prefix:
        for i, r in enumerate(results):
            svg = render_tree_svg(r.tree)
            svg_path = f"{args.out_svg_prefix}{i + 1}.svg"
            with open(svg_path, "w", encoding="utf-8") as fh:
                fh.write(svg)
            _log(f"wrote {svg_path}", "ok")
            if args.png:
                png_path = f"{args.out_svg_prefix}{i + 1}.png"
                if svg_to_png(svg, png_path):
                    _log(f"wrote {png_path}", "ok")
                else:
                    _log("PNG skipped (pip install cairosvg to enable)", "warn")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from .server import serve
    serve(host=args.host, port=args.port, open_browser=not args.no_browser)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="threat_modeler", description="UxV threat-modeling engine")
    p.add_argument("--version", action="version", version=f"threat_modeler {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("models", help="list selectable models/providers").set_defaults(func=cmd_models)

    ss = sub.add_parser("serve", help="run the local web UI")
    ss.add_argument("--host", default="127.0.0.1")
    ss.add_argument("--port", type=int, default=8000)
    ss.add_argument("--no-browser", action="store_true", help="do not auto-open a browser tab")
    ss.set_defaults(func=cmd_serve)

    so = sub.add_parser("openxsampp", help="re-emit deterministic OpenXSAM++ XML")
    so.add_argument("file", help="OpenXSAM++ .xml file")
    so.add_argument("-c", "--config", help="config JSON overlay (else embedded config)")
    so.set_defaults(func=cmd_openxsampp)

    spa = sub.add_parser("paths", help="DFS logical paths + atoms")
    spa.add_argument("file", help="OpenXSAM++ .xml file")
    spa.add_argument("-c", "--config", help="config JSON overlay (else embedded config)")
    spa.add_argument("--entry", nargs="+", required=True, help="entry node guid(s)")
    spa.add_argument("--endpoint", required=True, help="endpoint node guid")
    spa.add_argument("--max-len", type=int, default=16)
    spa.add_argument("--max-paths", type=int, default=400)
    spa.set_defaults(func=cmd_paths)

    sr = sub.add_parser("run", help="full pipeline -> attack tree(s)")
    sr.add_argument("file", help="OpenXSAM++ .xml file")
    sr.add_argument("-c", "--config", help="config JSON overlay (else embedded config)")
    sr.add_argument("--provider", choices=[ANTHROPIC, OPENAI, OLLAMA_CLOUD, OLLAMA],
                    default=DEFAULT_PROVIDER)
    sr.add_argument("--model", default=DEFAULT_MODEL, help=f"model id (default {DEFAULT_MODEL})")
    sr.add_argument("--api-key", help="Anthropic/OpenAI-compatible key (or Ollama bearer token)")
    sr.add_argument("--base-url", help="API base URL for openai/ollama providers "
                    f"(openai default {DEFAULT_OPENAI_BASE_URL})")
    sr.add_argument("--scenarios", help="scenarios JSON file (else agent-derive)")
    sr.add_argument("--no-rag", action="store_true", help="skip Attack-RAG component enrichment")
    sr.add_argument("--rag-top-k", type=int, default=5, help="RAG chunks fetched per corpus (1-100)")
    sr.add_argument("--rag-url", help="Attack-RAG base URL (or ATTACK_RAG_URL env)")
    sr.add_argument("--max-len", type=int, default=16)
    sr.add_argument("--max-paths", type=int, default=400)
    sr.add_argument("--out-json", help="write trees JSON to this path")
    sr.add_argument("--out-svg-prefix", help="write per-tree SVG to <prefix>N.svg")
    sr.add_argument("--png", action="store_true", help="also emit PNG (needs cairosvg)")
    sr.set_defaults(func=cmd_run)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, FileNotFoundError, json.JSONDecodeError) as exc:
        _log(f"error: {exc}", "err")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
