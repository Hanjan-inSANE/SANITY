"""End-to-end orchestration for attack-tree generation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .graph import EngineGraph, build_engine_graph, scenario_paths, build_atoms
from .dfd import SystemModel
from . import stages
from .models import (
    ANTHROPIC,
    DEFAULT_OLLAMA_BASE_URL,
    normalize_provider,
)
from .validator import ValidationIssue, validate_attack_tree


Logger = Callable[[str, str], None]  # (message, level) level in {info,ok,warn,err}


def _default_log(msg: str, level: str = "info") -> None:
    print(f"[{level}] {msg}")


def _count_leaves(node: Dict[str, Any]) -> int:
    """Count leaf nodes (each a single grounded attack) in a tree."""
    if not isinstance(node, dict):
        return 0
    children = node.get("children") or []
    if not children:
        return 1
    return sum(_count_leaves(c) for c in children)


def _tree_depth(node: Dict[str, Any]) -> int:
    if not isinstance(node, dict):
        return 0
    children = node.get("children") or []
    return 1 + (max((_tree_depth(c) for c in children), default=0))


@dataclass
class TreeResult:
    scenario: Dict[str, Any]
    tree: Dict[str, Any]
    validation_issues: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class PipelineOptions:
    model: str
    api_key: str = ""
    provider: str = ANTHROPIC
    base_url: str = DEFAULT_OLLAMA_BASE_URL   # LLM base URL (openai/ollama)
    use_rag: bool = True                       # enrich components via Attack-RAG
    rag_top_k: int = 5                          # chunks fetched PER corpus
    rag_base_url: Optional[str] = None         # None -> ATTACK_RAG_URL env / default
    max_path_len: int = 16
    max_paths: int = 400


def _channel_between(graph: EngineGraph, src: str, dst: str):
    for to, ch in graph.adj.get(src, []):
        if to == dst:
            return ch
    return None


def _describe_paths(graph: EngineGraph, paths: List[List[str]]) -> List[Dict[str, Any]]:
    known_components = [{"id": n.id, "label": n.label} for n in graph.nodes]
    known_channels = [{"id": e.id, "label": e.label} for e in graph.edges]
    out: List[Dict[str, Any]] = []
    for p in paths:
        components = [{"id": nid, "label": graph.by_id[nid].label} for nid in p]
        channels: List[Dict[str, Any]] = []
        for i in range(len(p) - 1):
            ch = _channel_between(graph, p[i], p[i + 1])
            if ch is None:
                continue
            channels.append({
                "id": ch.id,
                "label": ch.label,
                "from": graph.by_id[p[i]].label,
                "to": graph.by_id[p[i + 1]].label,
                "tech": ch.tech or "unspecified",
                "interface": ch.iface or "unspecified",
            })
        out.append({
            "components": components,
            "channels": channels,
            "knownComponents": known_components,
            "knownChannels": known_channels,
        })
    return out


def _best_validation(
    tree: Dict[str, Any],
    path_contexts: List[Dict[str, Any]],
    entry_labels: List[str],
    endpoint_label: str,
) -> List[ValidationIssue]:
    if not path_contexts:
        return []
    issue_sets = [
        validate_attack_tree(tree, ctx, entry_labels, [endpoint_label])
        for ctx in path_contexts
    ]
    return min(issue_sets, key=lambda xs: (sum(1 for i in xs if i.severity == "err"), len(xs)))


def run_pipeline(
    model_or_graph,
    options: PipelineOptions,
    scenarios: Optional[List[Dict[str, Any]]] = None,
    config: Optional[Dict[str, Dict[str, object]]] = None,
    log: Optional[Logger] = None,
    contexts: Optional[Dict[str, Dict[str, Any]]] = None,
    on_tree: Optional[Callable[[int, "TreeResult"], None]] = None,
) -> List[TreeResult]:
    """Run the full pipeline.

    ``contexts`` may carry Attack-RAG enrichment already produced on the
    Scenarios tab; when supplied it is reused instead of re-querying RAG.
    ``on_tree`` (index, TreeResult) is called as soon as each scenario's tree
    is assembled, so the UI can render trees progressively.

    ``model_or_graph`` may be a parsed SystemModel or an already-built
    EngineGraph.
    """
    log = log or _default_log
    options.provider = normalize_provider(options.provider)

    if isinstance(model_or_graph, EngineGraph):
        graph = model_or_graph
    elif isinstance(model_or_graph, SystemModel):
        graph = build_engine_graph(model_or_graph, config or {})
    else:
        raise TypeError("expected SystemModel or EngineGraph")

    log(f"system: {len(graph.nodes)} components, {len(graph.edges)} channels", "info")
    log(f"llm: provider={options.provider} model={options.model}", "info")

    # RAG: enrich each DFD component with source-grounded attack context.
    # Reuse enrichment already computed on the Scenarios tab when provided.
    contexts = dict(contexts) if contexts else {}
    if contexts:
        log(f"reusing Attack-RAG context for {len(contexts)} component(s) from Scenarios tab", "ok")
    elif options.use_rag:
        log("enriching components via Attack-RAG (TTP/CVE/CWE)", "info")
        try:
            contexts = stages.rag_enrich_components(
                graph, top_k=options.rag_top_k, base_url=options.rag_base_url, log=log,
            )
            log(f"  RAG: {len(contexts)}/{len(graph.nodes)} component(s) enriched", "ok")
        except Exception as exc:  # never let RAG break the run
            log(f"  RAG enrichment failed: {exc}", "warn")

    scenarios = list(scenarios or [])
    if not scenarios:
        log("no manual scenarios; deriving via agent (RAG-grounded)", "warn")
        scenarios = stages.derive_scenarios(
            options.api_key, options.model, graph, contexts=contexts,
            provider=options.provider, base_url=options.base_url, log=log,
        )
        log(f"derived {len(scenarios)} scenario(s)", "ok" if scenarios else "warn")

    results: List[TreeResult] = []
    for si, sc in enumerate(scenarios):
        log(f"[scenario {si + 1}/{len(scenarios)}] {sc['objective']}", "warn")
        paths = scenario_paths(
            graph, sc["entryIds"], sc["endpointId"],
            options.max_path_len, options.max_paths,
        )
        log(f"  DFS: {len(paths)} entry->endpoint path(s)", "info")
        if not paths:
            log("  no path from entry to endpoint; skipped", "err")
            continue

        path_contexts = _describe_paths(graph, paths)
        atom_set = build_atoms(graph, paths)
        log(f"  atoms: {len(atom_set.atoms)}", "info")

        subtrees: List[Dict[str, Any]] = []
        n_atoms = len(atom_set.atoms)
        for i, atom in enumerate(atom_set.atoms):
            tail = f" -> {atom.next_node.label}" if atom.next_node else " (endpoint)"
            log(f"  constructor {i + 1}/{n_atoms}: {atom.node.label}{tail}", "info")
            try:
                st = stages.construct_subtree(
                    options.api_key, options.model, atom,
                    context=contexts.get(atom.node.id),
                    provider=options.provider, base_url=options.base_url,
                )
                subtrees.append(st)
                n_leaves = _count_leaves(st)
                log(f"    OK sub-tree {i + 1}/{n_atoms} ({n_leaves} leaf attack(s))", "ok")
            except Exception as exc:
                log(f"    constructor failed: {exc}", "err")

        log(f"  assembling {len(subtrees)} sub-tree(s) + validating", "info")
        tree = stages.assemble(
            options.api_key, options.model, sc, subtrees, graph,
            dfd_paths=path_contexts, provider=options.provider, base_url=options.base_url,
        )

        entry_labels = [graph.by_id[i].label for i in sc["entryIds"] if i in graph.by_id]
        endpoint_label = graph.by_id[sc["endpointId"]].label if sc["endpointId"] in graph.by_id else sc["endpointId"]
        issues = _best_validation(tree, path_contexts, entry_labels, endpoint_label)
        for issue in issues:
            log(f"  validation {issue.severity}: {issue.code}: {issue.message}", "warn")

        tree_result = TreeResult(
            scenario=sc,
            tree=tree,
            validation_issues=[i.to_dict() for i in issues],
        )
        results.append(tree_result)
        log(f"  tree assembled ({_count_leaves(tree)} leaf attack(s), depth {_tree_depth(tree)})", "ok")
        if on_tree is not None:
            try:
                on_tree(si, tree_result)
            except Exception:  # a UI callback must never break the pipeline
                pass

    log(f"DONE - {len(results)} attack tree(s) generated.", "ok")
    return results
