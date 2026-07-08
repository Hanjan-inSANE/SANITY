"""Local web server that connects ``index.html`` to the Python engine."""

from __future__ import annotations

import json
import os
import threading
import webbrowser
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict

from .graph import build_engine_graph
from .openxsampp import generate_openxsampp, parse_openxsampp
from .models import (
    MODELS,
    DEFAULT_MODEL,
    DEFAULT_PROVIDER,
    DEFAULTS,
    DEFAULT_BASE_URLS,
    DEFAULT_OLLAMA_BASE_URL,
    DEFAULT_OPENAI_BASE_URL,
    OPENAI_PRESETS,
)
from .config_schema import NODE_FIELDS, EDGE_FIELDS


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _project_file(name: str) -> str:
    return os.path.join(ROOT, name)


def _provider(body: Dict[str, Any]) -> str:
    return str(body.get("provider") or DEFAULT_PROVIDER)


def _base_url(body: Dict[str, Any]) -> str:
    b = str(body.get("baseUrl") or "").strip()
    if b:
        return b
    return DEFAULT_BASE_URLS.get(_provider(body), "")


def _input_model_config(body: Dict[str, Any]):
    """Return (SystemModel, config) from a request body carrying an
    ``openxsampp`` document. The UI's ``config`` (edited annotations) wins; the
    config embedded in the OpenXSAM++ document is the fallback."""
    config = body.get("config") or {}
    model, embedded = parse_openxsampp(body["openxsampp"])
    return model, (config or embedded)


def _openxsampp(body: Dict[str, Any]) -> Dict[str, Any]:
    model, config = _input_model_config(body)
    return {"xml": generate_openxsampp(model, config)}


def _parse_openxsampp(body: Dict[str, Any]) -> Dict[str, Any]:
    """Load an OpenXSAM++ document directly into nodes/edges/config."""
    model, config = parse_openxsampp(body["xml"])
    return {
        "nodes": [asdict(n) for n in model.nodes],
        "edges": [asdict(e) for e in model.edges],
        "config": config,
    }


_POST_ROUTES = {
    "/api/openxsampp": _openxsampp,
    "/api/parse_openxsampp": _parse_openxsampp,
}


class Handler(BaseHTTPRequestHandler):
    server_version = "Threat Modeler/0.3"

    def log_message(self, *_args):
        pass

    def _send_json(self, obj: Any, status: int = 200) -> None:
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_file(self, path: str, content_type: str) -> None:
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            self._send_file(_project_file("index.html"), "text/html; charset=utf-8")
        elif path == "/api/models":
            self._send_json({
                "models": [asdict(m) for m in MODELS],
                "default": DEFAULT_MODEL,
                "defaultProvider": DEFAULT_PROVIDER,
                "defaults": DEFAULTS,
                "baseUrls": DEFAULT_BASE_URLS,
                "defaultOllamaBaseUrl": DEFAULT_OLLAMA_BASE_URL,
                "defaultOpenaiBaseUrl": DEFAULT_OPENAI_BASE_URL,
                "openaiPresets": OPENAI_PRESETS,
            })
        elif path == "/api/schema":
            self._send_json({"nodeFields": NODE_FIELDS, "edgeFields": EDGE_FIELDS})
        elif path.endswith(".xml") and "/" not in path[1:]:
            self._send_file(_project_file(path[1:]), "application/xml")
        elif path.endswith(".json") and "/" not in path[1:]:
            self._send_file(_project_file(path[1:]), "application/json")
        else:
            self.send_error(404)

    def _open_ndjson(self):
        """Start a newline-delimited JSON response and return an ``emit`` fn."""
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()

        def emit(obj: Any) -> None:
            try:
                self.wfile.write((json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8"))
                self.wfile.flush()
            except (BrokenPipeError, ConnectionError, ValueError):
                pass

        return emit

    def _derive_stream(self, body: Dict[str, Any]) -> None:
        """Stream Attack-RAG enrichment + scenario derivation as NDJSON.

        Emits ``log`` events for each per-component RAG query and the chunks it
        returns, then a ``result`` carrying the derived scenarios and the RAG
        ``contexts`` (so the Run tab can reuse them without re-querying)."""
        from . import stages

        emit = self._open_ndjson()

        def log(m: str, lvl: str = "info") -> None:
            emit({"type": "log", "msg": m, "level": lvl})

        try:
            model, config = _input_model_config(body)
            graph = build_engine_graph(model, config)
            provider = _provider(body)
            base_url = _base_url(body)
            api_key = str(body.get("apiKey") or "")

            contexts: Dict[str, Any] = {}
            if bool(body.get("useRag", True)):
                log("enriching components via Attack-RAG (TTP/CVE/CWE)", "info")
                try:
                    contexts = stages.rag_enrich_components(
                        graph,
                        top_k=int(body.get("ragTopK", 5)),
                        base_url=(body.get("ragUrl") or None),
                        log=log,
                    )
                    log(f"  RAG: {len(contexts)}/{len(graph.nodes)} component(s) enriched", "ok")
                except Exception as exc:  # RAG must never break derivation
                    log(f"  RAG enrichment failed: {exc}", "warn")
            else:
                log("Attack-RAG disabled — deriving from the graph alone", "warn")

            log("deriving scenarios (RAG-grounded LLM inference)…", "info")
            scenarios = stages.derive_scenarios(
                api_key, body["model"], graph,
                contexts=contexts, provider=provider, base_url=base_url, log=log,
            )
            log(f"derived {len(scenarios)} scenario(s)", "ok" if scenarios else "warn")
            emit({"type": "result", "scenarios": scenarios, "contexts": contexts})
        except Exception as exc:
            emit({"type": "error", "error": f"{type(exc).__name__}: {exc}"})

    def _run_stream(self, body: Dict[str, Any]) -> None:
        from .pipeline import run_pipeline, PipelineOptions

        emit = self._open_ndjson()

        try:
            model, config = _input_model_config(body)
            graph = build_engine_graph(model, config)
            options = PipelineOptions(
                provider=_provider(body),
                model=body["model"],
                api_key=str(body.get("apiKey") or ""),
                base_url=_base_url(body),
                use_rag=bool(body.get("useRag", True)),
                rag_top_k=int(body.get("ragTopK", 5)),
                rag_base_url=(body.get("ragUrl") or None),
                max_path_len=int(body.get("maxLen", 16)),
                max_paths=int(body.get("maxPaths", 400)),
            )
            def on_tree(index: int, tr: Any) -> None:
                emit({
                    "type": "tree",
                    "index": index,
                    "scenario": tr.scenario,
                    "tree": tr.tree,
                    "validationIssues": tr.validation_issues,
                })

            results = run_pipeline(
                graph, options,
                scenarios=body.get("scenarios") or None,
                contexts=body.get("contexts") or None,
                on_tree=on_tree,
                log=lambda m, lvl="info": emit({"type": "log", "msg": m, "level": lvl}),
            )
            emit({"type": "result",
                  "trees": [
                      {
                          "scenario": r.scenario,
                          "tree": r.tree,
                          "validationIssues": r.validation_issues,
                      }
                      for r in results
                  ]})
        except Exception as exc:
            emit({"type": "error", "error": f"{type(exc).__name__}: {exc}"})

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception as exc:
            self._send_json({"error": f"bad request body: {exc}"}, status=400)
            return

        if path == "/api/run":
            self._run_stream(body)
            return

        if path == "/api/derive_scenarios":
            self._derive_stream(body)
            return

        handler = _POST_ROUTES.get(path)
        if handler is None:
            self.send_error(404)
            return
        try:
            self._send_json(handler(body))
        except Exception as exc:
            self._send_json({"error": f"{type(exc).__name__}: {exc}"}, status=400)


def serve(host: str = "127.0.0.1", port: int = 8000, open_browser: bool = True) -> None:
    httpd = ThreadingHTTPServer((host, port), Handler)
    url = f"http://{host}:{port}/"
    print(f"Threat Modeler server running at {url}")
    print("Engine runs in Python; the browser is the UI. Press Ctrl+C to stop.")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping...")
        httpd.shutdown()


if __name__ == "__main__":
    serve()
