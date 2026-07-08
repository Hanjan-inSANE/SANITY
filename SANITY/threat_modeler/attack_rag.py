"""
Attack RAG client — source-grounded threat retrieval.

Speaks the contract in `agent-integration.md`: the tool NEVER touches
ChromaDB or the admin API; it only calls the RAG server's `POST /query`.
Implemented with the standard library (urllib) so it adds no dependency.

Design rules honored from the guide:
  * fail-closed: on timeout/connection/HTTP error we raise RAGError and the
    caller degrades gracefully (component just gets no attack_context) — we
    never fabricate results.
  * exact-id friendly: the server does exact lookup for CVE/CWE/ATT&CK/
    SPARTA ids first, then merges semantic search, so we simply pass the
    component's config (products, protocols, ids) as the query.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

DEFAULT_RAG_URL = "http://100.77.84.85:9843"
DEFAULT_RAG_PORT = 9843   # Attack-RAG service port (per the MCP tool contract)

# Corpora in the Attack-RAG store. Each is queried SEPARATELY (via the ``where``
# metadata filter) so every category is represented in a component's context
# instead of one corpus crowding out the others. The strings must match the
# server's ``source.corpus`` metadata values — adjust here if your server differs.
RAG_CORPORA = [
    "mitre_attack_enterprise",
    "mitre_attack_ics",
    "sparta",
    "cve",
    "cwe",
]


class RAGError(RuntimeError):
    pass


def rag_url(base_url: Optional[str] = None) -> str:
    """Normalize a user-supplied Attack-RAG base into a full ``scheme://host:port``.

    Tailscale only makes the host *reachable*; urllib still needs a complete
    URL. So a bare address like ``100.95.158.13`` (no scheme, no port) is
    completed to ``http://100.95.158.13:9843``. A value that already carries a
    scheme and/or port is respected as-is.
    """
    raw = (base_url or os.getenv("ATTACK_RAG_URL", DEFAULT_RAG_URL)).strip().rstrip("/")
    if not raw:
        raw = DEFAULT_RAG_URL
    if "://" not in raw:
        raw = "http://" + raw
    parsed = urlparse(raw)
    try:
        has_port = parsed.port is not None
    except ValueError:  # malformed port in the input; let it surface downstream
        has_port = True
    if not has_port and parsed.hostname:
        raw = f"{parsed.scheme}://{parsed.hostname}:{DEFAULT_RAG_PORT}{parsed.path}"
    return raw.rstrip("/")


def attack_rag_query(
    query: str,
    top_k: int = 8,
    include_documents: bool = True,
    base_url: Optional[str] = None,
    collections: Optional[List[str]] = None,
    where: Optional[Dict[str, Any]] = None,
    timeout: float = 120.0,
) -> Dict[str, Any]:
    """Call POST /query and return the parsed response (per the guide)."""
    query = (query or "").strip()
    if not query:
        raise ValueError("query must be a non-empty string")
    if top_k < 1 or top_k > 100:
        raise ValueError("top_k must be between 1 and 100")

    payload: Dict[str, Any] = {
        "query": query,
        "top_k": top_k,
        "include_documents": include_documents,
    }
    if collections:
        payload["collections"] = collections
    if where:
        payload["where"] = where

    data = json.dumps(payload).encode("utf-8")
    url = rag_url(base_url) + "/query"
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RAGError(f"Attack RAG query failed: HTTP {exc.code}: {body}") from exc
    except urllib.error.URLError as exc:
        raise RAGError(f"Attack RAG unavailable ({url}): {exc}") from exc
    except json.JSONDecodeError as exc:
        raise RAGError(f"Attack RAG response was not valid JSON: {exc}") from exc


def format_rag_context(response: Dict[str, Any], max_chars: int = 6000) -> str:
    """Compact, citation-friendly text block from a RAG response."""
    parts: List[str] = []
    budget = max_chars
    for row in response.get("results", []) or []:
        src = row.get("source", {}) or {}
        header = (
            f"[rank={row.get('rank')} score={row.get('score')} "
            f"corpus={src.get('corpus')} id={src.get('external_id')} "
            f"name={src.get('name')}]"
        )
        block = f"{header}\n{(row.get('document') or '').strip()}".strip()
        if len(block) > budget:
            parts.append(block[:budget])
            break
        parts.append(block)
        budget -= len(block)
        if budget <= 0:
            break
    return "\n\n---\n\n".join(parts)


def rag_findings(response: Dict[str, Any], limit: int = 8) -> List[Dict[str, Any]]:
    """Structured, node-attachable findings (dedup by external_id/id)."""
    out: List[Dict[str, Any]] = []
    seen: set = set()
    for row in (response.get("results", []) or [])[:limit]:
        src = row.get("source", {}) or {}
        key = src.get("external_id") or row.get("id")
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "id": src.get("external_id") or row.get("id"),
            "name": src.get("name"),
            "corpus": src.get("corpus"),
            "url": src.get("url"),
            "score": row.get("score"),
            "summary": (row.get("document") or "").strip()[:700],
            "source_locator": src.get("source_locator"),
        })
    return out


def build_component_query(component: Any, protocols: Optional[List[str]] = None) -> str:
    """Build a RAG query string from a component's OpenXSAM++ config.

    ``component`` is a :class:`threat_modeler.graph.GComponent`. We concatenate the
    label, OS, SBOM, services, chips, modules, and adjacent channel protocols
    so the server can hit exact ids (products/CVEs) and semantic matches.
    """
    sw = getattr(component, "software", {}) or {}
    hw = getattr(component, "hardware", {}) or {}
    terms: List[str] = [getattr(component, "label", "")]
    if sw.get("os"):
        terms.append(str(sw["os"]))
    for key in ("sbom", "services"):
        terms += [str(x) for x in (sw.get(key) or [])]
    for key in ("chips", "modules"):
        terms += [str(x) for x in (hw.get(key) or [])]
    terms += [str(p) for p in (protocols or [])]
    # de-dup while preserving order, drop blanks
    seen: set = set()
    uniq = []
    for t in terms:
        t = t.strip()
        if t and t.lower() not in seen:
            seen.add(t.lower())
            uniq.append(t)
    return " ".join(uniq)[:500]
