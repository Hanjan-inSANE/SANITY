"""
LLM stages of the pipeline (+ RAG-based grounding).

Grounding source changed: instead of few-shot *web search*, each DFD
component is enriched with source-grounded attack context (TTP/CVE/CWE)
retrieved from the external Attack-RAG server (see :mod:`threat_modeler.attack_rag`
and ``agent-integration.md``). Scenarios and per-atom sub-trees are then
constructed on top of that grounded context.

"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional

from .graph import EngineGraph, Atom, compact_graph
from .llm import call_and_parse
from .models import ANTHROPIC
from . import attack_rag


Logger = Callable[[str, str], None]


# --- RAG: per-component attack context (replaces web-search few-shot) -------

def _protocols_for(graph: EngineGraph, comp_id: str) -> List[str]:
    """Channel technologies/labels adjacent to a component (in + out)."""
    out: List[str] = []
    for e in graph.edges:
        if e.source == comp_id or e.target == comp_id:
            out.append(e.tech or e.label)
    return out


def _enrich_one_component(
    query: str,
    top_k: int,
    base_url: Optional[str],
    log_fn,
) -> Optional[Dict[str, Any]]:
    """Retrieve attack context for one component, ONE corpus at a time.

    Each corpus in :data:`attack_rag.RAG_CORPORA` is queried separately with a
    ``where`` metadata filter so every category (ATT&CK, SPARTA, CVE, CWE) is
    represented rather than one corpus dominating a single blended top-k. Results
    are de-duplicated by evidence id across corpora. If per-corpus filtering
    yields nothing at all (e.g. the server ignores ``where``), fall back to one
    unfiltered query so retrieval still works."""
    findings: List[Dict[str, Any]] = []
    context_blocks: List[str] = []
    seen_ids: set = set()
    any_error = False

    for corpus in attack_rag.RAG_CORPORA:
        try:
            resp = attack_rag.attack_rag_query(
                query, top_k=top_k, base_url=base_url, where={"corpus": corpus},
            )
        except attack_rag.RAGError as exc:
            any_error = True
            log_fn(f"      {corpus}: unavailable ({exc})", "warn")
            continue
        corpus_findings = attack_rag.rag_findings(resp, limit=top_k)
        kept = 0
        for f in corpus_findings:
            fid = f.get("id")
            if fid and fid in seen_ids:
                continue
            if fid:
                seen_ids.add(fid)
            findings.append(f)
            kept += 1
        if kept:
            block = attack_rag.format_rag_context(resp, max_chars=1500)
            if block:
                context_blocks.append(f"### corpus: {corpus}\n{block}")
        log_fn(f"      {corpus}: {kept} chunk(s)", "ok" if kept else "dim")
        for f in corpus_findings[:3]:
            score = f.get("score")
            score_s = f"{score:.3f}" if isinstance(score, (int, float)) else str(score)
            snippet = " ".join((f.get("summary") or "").split())[:140]
            log_fn(f"        · {f.get('id') or '?'} ({f.get('name') or 'n/a'}) "
                   f"score={score_s} — {snippet}", "dim")

    if not findings:
        if any_error:
            return None
        # Server returned nothing per-corpus (perhaps it ignores `where`) — one
        # unfiltered query as a fallback so the component still gets context.
        try:
            resp = attack_rag.attack_rag_query(query, top_k=top_k, base_url=base_url)
        except attack_rag.RAGError as exc:
            log_fn(f"      fallback query unavailable ({exc})", "warn")
            return None
        findings = attack_rag.rag_findings(resp, limit=top_k)
        if not findings:
            return None
        context_blocks = [attack_rag.format_rag_context(resp, max_chars=6000)]
        log_fn(f"      (no per-corpus split available) {len(findings)} blended chunk(s)", "warn")

    return {
        "query": query,
        "context": "\n\n".join(context_blocks),
        "findings": findings,
    }


def rag_enrich_components(
    graph: EngineGraph,
    top_k: int = 5,
    base_url: Optional[str] = None,
    log: Optional[Logger] = None,
) -> Dict[str, Dict[str, Any]]:
    """Enrich each component with attack context, retrieved PER CORPUS.

    Returns ``{component_id: {query, context, findings}}``. ``top_k`` is the
    number of chunks fetched *per corpus* (not in total). Fail-closed and
    per-component: if the server is down or a query errors, that component simply
    gets no context (never fabricated).
    """
    def _log(m: str, lvl: str = "info") -> None:
        if log:
            log(m, lvl)

    contexts: Dict[str, Dict[str, Any]] = {}
    for n in graph.nodes:
        query = attack_rag.build_component_query(n, _protocols_for(graph, n.id))
        if not query.strip():
            _log(f"    RAG {n.label}: no query terms (component unconfigured); skipped", "dim")
            continue
        _log(f"    RAG query [{n.label}] (top_k={top_k}/corpus) -> \"{query}\"", "info")
        result = _enrich_one_component(query, top_k, base_url, _log)
        if result:
            contexts[n.id] = result
            _log(f"    RAG hits [{n.label}]: {len(result['findings'])} chunk(s) across corpora", "ok")
    return contexts


def _context_summary(contexts: Dict[str, Dict[str, Any]], graph: EngineGraph) -> List[Dict[str, Any]]:
    """Compact per-component attack-context summary for the scenario prompt."""
    by_id = {n.id: n for n in graph.nodes}
    out: List[Dict[str, Any]] = []
    for cid, ctx in contexts.items():
        node = by_id.get(cid)
        out.append({
            "id": cid,
            "label": node.label if node else cid,
            "findings": [
                {"id": f.get("id"), "name": f.get("name"), "corpus": f.get("corpus")}
                for f in (ctx.get("findings") or [])[:6]
            ],
        })
    return out


# --- scenario derivation (grounded on RAG context) -------------------------

def _build_id_resolver(graph: EngineGraph) -> Callable[[Any], Optional[str]]:
    """Map a model-supplied component reference back to a real node id.

    Small/local models often echo a component's *label* ("RC Transmitter") or a
    case-mangled id instead of the exact 36-char guid. Rather than silently drop
    those scenarios, resolve leniently: exact id, case-insensitive id, then
    exact (case-insensitive) label."""
    by_id = {n.id: n.id for n in graph.nodes}
    by_id_lower = {n.id.lower(): n.id for n in graph.nodes}
    by_label_lower: Dict[str, str] = {}
    for n in graph.nodes:
        by_label_lower.setdefault(n.label.strip().lower(), n.id)

    def resolve(val: Any) -> Optional[str]:
        if val is None:
            return None
        s = str(val).strip()
        if not s:
            return None
        if s in by_id:
            return by_id[s]
        low = s.lower()
        return by_id_lower.get(low) or by_label_lower.get(low)

    return resolve


def derive_scenarios(
    api_key: str,
    model: str,
    graph: EngineGraph,
    contexts: Optional[Dict[str, Dict[str, Any]]] = None,
    provider: str = ANTHROPIC,
    base_url: Optional[str] = None,
    log: Optional[Logger] = None,
) -> List[Dict[str, Any]]:
    """Derive scenarios grounded in real graph node ids + RAG attack context."""
    def _log(m: str, lvl: str = "info") -> None:
        if log:
            log(m, lvl)

    system = (
        "You are a senior offensive-security strategist specializing in unmanned"
        "systems (UxV: UAV/UGV/UUV/USV) and their control/communications stack"
        "Enumerate possible concrete scenarios (as much as possible) for a logical skeleton of an UxV attack-tree."
        "Given components, directed channels, and per-component attack context "
        "(retrieved TTP/CVE/CWE evidence), identify plausible attack scenarios. "
        "Each scenario = an attacker objective, one or more ENTRY components "
        ", and exactly one ENDPOINT component (whose "
        "compromise or misuse achieves the objective). Ground objectives in the "
        "provided attack context where possible. Use ONLY component ids from the "
        "input, copied EXACTLY as given (they are opaque identifiers). Output "
        "STRICT JSON array, no prose: "
        '[{"objective":str,"entryIds":[id,...],"endpointId":id,"rationale":str}]'
    )
    cg = compact_graph(graph)
    payload = {
        "components": cg["components"],
        "channels": cg["channels"],
        "attackContext": _context_summary(contexts or {}, graph),
    }
    arr = call_and_parse(
        api_key, model, system, json.dumps(payload), max_tokens=5000,
        provider=provider, base_url=base_url,
    )
    raw = arr if isinstance(arr, list) else []
    if not raw:
        _log("scenario derivation: model returned no scenario array (or empty)", "warn")
        return []

    resolve = _build_id_resolver(graph)
    out: List[Dict[str, Any]] = []
    dropped = 0
    for s in raw:
        if not isinstance(s, dict):
            dropped += 1
            continue
        endpoint = resolve(s.get("endpointId"))
        entries: List[str] = []
        for i in (s.get("entryIds") or []):
            r = resolve(i)
            if r and r not in entries:
                entries.append(r)
        if endpoint and entries:
            out.append({
                "objective": s.get("objective", ""),
                "entryIds": entries,
                "endpointId": endpoint,
                "rationale": s.get("rationale", ""),
            })
        else:
            dropped += 1
            reason = ("endpoint id unresolved" if not endpoint
                      else "no resolvable entry id")
            _log(
                f"  dropped scenario \"{str(s.get('objective', ''))[:60]}\": "
                f"{reason} (endpointId={s.get('endpointId')!r}, entryIds={s.get('entryIds')!r})",
                "dim",
            )
    lvl = "ok" if out else "warn"
    _log(f"scenario parse: {len(raw)} from model, {len(out)} valid, {dropped} dropped", lvl)
    if not out and dropped:
        _log(
            "  → the model did not reference valid component ids/labels; try a "
            "stronger model, or check the component labels match the graph.",
            "warn",
        )
    return out


# --- Sub-Tree Constructor (per atom, RAG-grounded) -------------------------

_CONSTRUCTOR_SYSTEM = (
    "You are the Sub-Tree Constructor of an attack-tree generator. You receive "
    "ONE atom: a single component plus its channels, a local objective, and "
    "SOURCE-GROUNDED attack context retrieved from an Attack-RAG store "
    "(ATT&CK/SPARTA/CVE/CWE chunks, each with an id, name, and summary). Reason "
    "internally (do not reveal chain-of-thought) and build a small AND/OR tree "
    "of UNIFORM nodes whose ROOT is the given local objective and whose "
    "descendants decompose it into concrete, grounded attacks on THIS "
    "component.\n"
    "UNIFORM NODE MODEL — do NOT use different node 'kind's; EVERY node has the "
    "SAME shape and MUST carry:\n"
    "  - 'summary': one line stating the abstract attack method AND the objective "
    "it achieves (e.g. 'Spoof GNSS L1 signals to feed the FC a false position, "
    "enabling navigation takeover'). The ROOT node's summary is the given local "
    "objective.\n"
    "  - 'attack_context': 2-4 sentences of REASONED, component-specific "
    "mechanism synthesized FROM the retrieved chunks — the entry vector via this "
    "component's actual software/hardware/services/channels and the resulting "
    "effect. Ground every claim in the provided findings; do not invent.\n"
    "  - 'evidence': array of {\"id\":str,\"note\":str} citing retrieved ids "
    "(CVE-…, CWE-…, T####, SV-…) that APPEAR in the context, each with a "
    "one-line relevance note. LEAF nodes MUST have >= 1; grouping nodes cite the "
    "evidence backing that approach.\n"
    "  - 'logic': 'AND' or 'OR' — how this node's CHILDREN combine to achieve it "
    "(AND = all required; OR = any one suffices, and an OR needs >= 2 real "
    "alternatives). OMIT 'logic' and 'children' on leaves.\n"
    "  - 'children': array of child nodes (omit on leaves).\n"
    "RULES:\n"
    "  - Every node represents EXACTLY ONE thing; no two nodes may describe the "
    "same or semantically overlapping goal/technique.\n"
    "  - A LEAF is ONE concrete, directly-executable operation — name the exact "
    "interface/message/parameter/tool. No abstract capabilities. If nothing in "
    "the context supports a leaf, omit it; never fabricate evidence.\n"
    "  - Do not claim a passive relay is compromised; model passthrough/trust "
    "abuse when that fits.\n"
    "Output STRICT JSON only, a single root node of the form: "
    '{"summary":str,"attack_context":str,"evidence":[{"id":str,"note":str}],'
    '"logic"?:"AND"|"OR","children"?:[node...]}.'
)


def construct_subtree(
    api_key: str,
    model: str,
    atom: Atom,
    context: Optional[Dict[str, Any]] = None,
    provider: str = ANTHROPIC,
    base_url: Optional[str] = None,
) -> Dict[str, Any]:
    if atom.exit_edge is not None and atom.next_node is not None:
        tech = atom.exit_edge.tech or atom.exit_edge.label
        local_obj = (
            f'Establish or use attacker-controlled effect at "{atom.node.label}" '
            f'so the effect advances to "{atom.next_node.label}" through channel "{tech}". '
            "If this component is only a passive relay, model channel passthrough "
            "or trust abuse rather than unsupported component compromise."
        )
    else:
        local_obj = f'Achieve the final attacker impact on endpoint "{atom.node.label}".'

    exit_channel: Optional[Dict[str, Any]] = None
    if atom.exit_edge is not None and atom.next_node is not None:
        exit_channel = {
            "to": atom.next_node.label,
            "tech": atom.exit_edge.tech or "unspecified",
            "label": atom.exit_edge.label,
            "interface": atom.exit_edge.iface or "unspecified",
        }

    ctx = context or {}
    # Retrieved chunks the model must reason over, presented explicitly so each
    # method leaf can be grounded in a specific finding (id + name + summary).
    retrieved = [
        {
            "id": f.get("id"),
            "name": f.get("name"),
            "corpus": f.get("corpus"),
            "summary": f.get("summary"),
        }
        for f in (ctx.get("findings") or [])
    ]
    payload = {
        "component": {
            "id": atom.node.id,
            "label": atom.node.label,
            "type": atom.node.type,
            "software": atom.node.software,
            "hardware": atom.node.hardware,
        },
        "incomingChannels": [
            {"from": e.source, "label": e.label, "tech": e.tech or "unspecified"}
            for e in atom.in_edges
        ],
        "exitChannel": exit_channel,
        "localObjective": local_obj,
        # Raw per-corpus chunk text to synthesize from, plus the structured
        # findings whose ids are the ONLY ones allowed in 'evidence'.
        "retrievedContext": (ctx.get("context") or "(none)")[:6000],
        "retrievedEvidence": retrieved,
    }
    return call_and_parse(
        api_key, model, _CONSTRUCTOR_SYSTEM, json.dumps(payload), max_tokens=6000,
        provider=provider, base_url=base_url,
    )


# --- Attack-Tree Assembler (Item 3: AND/OR only, order via nesting) --------

_ASSEMBLER_SYSTEM = (
    "You are the Attack-Tree Assembler. Merge the per-atom sub-trees into ONE "
    "attack tree of UNIFORM nodes rooted at the scenario objective (the endpoint "
    "impact).\n"
    "UNIFORM NODE MODEL — do NOT use node 'kind's. EVERY node has the SAME shape "
    "and carries: 'summary' (one line: abstract attack method + the objective it "
    "achieves; the ROOT's summary is the scenario objective), 'attack_context' "
    "(reasoned, component-specific mechanism), 'evidence' ([{\"id\",\"note\"}] "
    "grounded ids), 'logic' ('AND'|'OR' over its children; omit on leaves), "
    "optional 'dfd_component'/'dfd_channel', and 'children'.\n"
    "STRUCTURE RULES:\n"
    "  1. The root MAY have one or more children; do not force a single child.\n"
    "  2. Express sequential order by PARENT/CHILD nesting: a prerequisite is an "
    "ANCESTOR of what it enables. Do NOT invent a SEQ node or stage_index.\n"
    "  3. AND = all children required; OR = any one child suffices. An OR must "
    "have >= 2 real alternatives.\n"
    "  4. Decompose the entry->endpoint DFD path as nested AND/OR from the "
    "endpoint objective down to entry-reachable leaves, using only components/"
    "channels from the provided DFD path (mark genuine exceptions "
    "out_of_band=true or precondition=true with notes).\n"
    "  5. Do not call a passive relay compromised unless justified by the inputs.\n"
    "  6. Every node represents EXACTLY ONE thing; deduplicate semantically "
    "overlapping nodes (if two sub-trees produced the same node, keep one).\n"
    "  7. A LEAF is ONE concrete, directly-executable operation (name the exact "
    "interface/message/parameter/tool), grounded via 'attack_context' and "
    "'evidence' — not stuffed into 'summary'. Drop abstract/unsupported leaves; "
    "never fabricate evidence.\n"
    "  8. PRESERVE grounding: carry each node's 'summary', 'attack_context' and "
    "'evidence' from the sub-trees. When you deduplicate overlapping nodes, keep "
    "the richer 'attack_context' and UNION 'evidence' (dedupe by id). Never drop "
    "a node's attack_context/evidence.\n"
    "Annotate nodes with dfd_component/dfd_channel where they map to the path.\n"
    "Output STRICT JSON, no prose, a single root node of the form: "
    '{"summary":str,"attack_context":str,"evidence":[{"id":str,"note":str}],'
    '"logic"?:"AND"|"OR","dfd_component"?:str,"dfd_channel"?:str,'
    '"out_of_band"?:bool,"precondition"?:bool,"notes"?:str,"children"?:[...]}.'
)


def assemble(
    api_key: str,
    model: str,
    scenario: Dict[str, Any],
    subtrees: List[Dict[str, Any]],
    graph: EngineGraph,
    dfd_paths: Optional[List[Dict[str, Any]]] = None,
    provider: str = ANTHROPIC,
    base_url: Optional[str] = None,
) -> Dict[str, Any]:
    """Merge per-atom sub-trees into one AND/OR attack tree (no SEQ)."""
    payload = {
        "objective": scenario["objective"],
        "entry": scenario["entryIds"],
        "endpoint": scenario["endpointId"],
        "subTrees": subtrees,
        "topology": compact_graph(graph)["channels"],
        "dfdPaths": dfd_paths or [],
    }
    return call_and_parse(
        api_key, model, _ASSEMBLER_SYSTEM, json.dumps(payload), max_tokens=8192,
        provider=provider, base_url=base_url,
    )
