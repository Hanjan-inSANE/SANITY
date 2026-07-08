"""
Deterministic engine: config injection, DFS logical-path extraction, and
atom decomposition (DefenseWeaver §IV-B2).

Formal definitions (used consistently across the codebase and README):

  * *directed graph*  G = (V, E) built from OpenXSAM++, V = components,
    E = directed channels (data flows).
  * *logical path*    an acyclic (simple) path from a threat-scenario
    entry component to its single endpoint component. All such paths are
    enumerated with depth-first search; cyclic routes are discarded
    because revisiting a compromised component adds nothing for TARA.
  * *atom*            a single node plus its directly connected channels,
    SPLIT by exit channel so each atom has exactly one *local attack
    objective* (propagate to the next node via one exit channel). The
    endpoint node additionally yields one *terminal* atom (final impact,
    no exit channel).

Path/depth caps are parameters (never hardcoded constants baked into the
algorithm) so callers/UI can guard against path explosion on large graphs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .dfd import SystemModel

# A configuration maps element guid -> {field_key: value, "__custom": [...]}.
Config = Dict[str, Dict[str, object]]


def normalize_config(obj: Optional[Dict[str, object]]) -> Config:
    """Accept either the bare ``{guid: {...}}`` config or the wrapped
    ``{"config": {guid: {...}}}`` envelope used by the exported/import
    annotation JSON files, and always return the bare mapping.
    """
    if not obj:
        return {}
    inner = obj.get("config")
    if isinstance(inner, dict):
        return inner  # unwrap the {"config": {...}} envelope
    return obj  # already the bare {guid: {...}} form


# --- config accessors ------------------------------------------------------

def _field(config: Config, guid: str, key: str) -> str:
    return str((config.get(guid, {}) or {}).get(key, "") or "").strip()


def _lines(value: str) -> List[str]:
    return [x.strip() for x in str(value or "").splitlines() if x.strip()]


def _custom(config: Config, guid: str) -> List[Dict[str, str]]:
    raw = (config.get(guid, {}) or {}).get("__custom", []) or []
    return [c for c in raw if c.get("k") and c.get("v")]


# --- engine graph ----------------------------------------------------------

@dataclass
class GComponent:
    id: str
    label: str
    type: str
    software: Dict[str, object]
    hardware: Dict[str, object]
    custom: List[Dict[str, str]]


@dataclass
class GChannel:
    id: str
    source: str
    target: str
    label: str
    tech: str
    iface: str
    data: str


@dataclass
class EngineGraph:
    nodes: List[GComponent]
    edges: List[GChannel]
    adj: Dict[str, List[Tuple[str, GChannel]]]        # node id -> [(to, channel)]
    by_id: Dict[str, GComponent]


def build_engine_graph(model: SystemModel, config: Optional[Config] = None) -> EngineGraph:
    """Inject function-level config into the parsed model, producing the
    directed graph the LLM stages reason over."""
    config = normalize_config(config)

    nodes = [
        GComponent(
            id=n.guid,
            label=n.label,
            type=n.type,
            software={
                "os": _field(config, n.guid, "sw.os"),
                "sbom": _lines(_field(config, n.guid, "sw.sbom")),
                "services": _lines(_field(config, n.guid, "sw.services")),
            },
            hardware={
                "chips": _lines(_field(config, n.guid, "hw.chips")),
                "modules": _lines(_field(config, n.guid, "hw.modules")),
                "debug": _field(config, n.guid, "hw.debug"),
            },
            custom=_custom(config, n.guid),
        )
        for n in model.nodes
    ]

    edges = [
        GChannel(
            id=e.guid,
            source=e.source,
            target=e.target,
            label=e.label,
            tech=_field(config, e.guid, "ch.tech"),
            iface=_field(config, e.guid, "ch.interface"),
            data=_field(config, e.guid, "ch.data") or e.label,
        )
        for e in model.edges
    ]

    adj: Dict[str, List[Tuple[str, GChannel]]] = {n.id: [] for n in nodes}
    for e in edges:
        if e.source in adj:
            adj[e.source].append((e.target, e))

    by_id = {n.id: n for n in nodes}
    return EngineGraph(nodes=nodes, edges=edges, adj=adj, by_id=by_id)


# --- logical path extraction (DFS) ----------------------------------------

def all_simple_paths(
    adj: Dict[str, List[Tuple[str, GChannel]]],
    start: str,
    goal: str,
    max_len: int = 16,
    max_paths: int = 400,
) -> List[List[str]]:
    """Enumerate every acyclic path start -> goal (node-id lists).

    ``max_len`` bounds path length (defense against path explosion);
    ``max_paths`` bounds the result count. Both are exposed to the caller.
    """
    out: List[List[str]] = []
    # stack of (node, path_so_far, visited_set)
    stack: List[Tuple[str, List[str], set]] = [(start, [start], {start})]
    while stack:
        node, path, seen = stack.pop()
        if node == goal:
            out.append(path)
            if len(out) >= max_paths:
                break
            continue
        if len(path) >= max_len:
            continue
        for to, _ch in adj.get(node, []):
            if to not in seen:
                stack.append((to, path + [to], seen | {to}))
    return out


def scenario_paths(
    graph: EngineGraph,
    entry_ids: List[str],
    endpoint_id: str,
    max_len: int = 16,
    max_paths: int = 400,
) -> List[List[str]]:
    """Union of all simple paths from each entry to the single endpoint."""
    result: List[List[str]] = []
    for entry in entry_ids:
        result.extend(
            all_simple_paths(graph.adj, entry, endpoint_id, max_len, max_paths)
        )
    return result


# --- atom construction -----------------------------------------------------

@dataclass
class Atom:
    node: GComponent
    in_edges: List[GChannel]
    exit_edge: Optional[GChannel]
    next_node: Optional[GComponent]
    kind: str                      # "propagate" | "terminal"


@dataclass
class AtomSet:
    on_nodes: List[str]
    atoms: List[Atom]


def build_atoms(graph: EngineGraph, paths: List[List[str]]) -> AtomSet:
    """Decompose the logical paths into atoms (§IV-B2, Atom Construction).

    One propagate-atom per (node, exit channel on a path); one terminal
    atom for each endpoint node that has no outgoing on-path channel.
    """
    on_nodes: set = set()
    on_edge_key: set = set()
    for p in paths:
        for n in p:
            on_nodes.add(n)
        for i in range(len(p) - 1):
            on_edge_key.add(p[i] + ">" + p[i + 1])

    end_set = {p[-1] for p in paths if p}
    atoms: List[Atom] = []
    ordered_nodes = sorted(on_nodes)  # deterministic atom order

    for nid in ordered_nodes:
        node = graph.by_id[nid]
        in_edges = [
            e for e in graph.edges
            if e.target == nid and (e.source + ">" + nid) in on_edge_key
        ]
        outs = [
            (to, ch) for (to, ch) in graph.adj.get(nid, [])
            if (nid + ">" + to) in on_edge_key
        ]
        if not outs and nid in end_set:
            atoms.append(
                Atom(node=node, in_edges=in_edges, exit_edge=None,
                     next_node=None, kind="terminal")
            )
        for to, ch in outs:
            atoms.append(
                Atom(node=node, in_edges=in_edges, exit_edge=ch,
                     next_node=graph.by_id[to], kind="propagate")
            )

    return AtomSet(on_nodes=ordered_nodes, atoms=atoms)


def compact_graph(graph: EngineGraph) -> Dict[str, object]:
    """A compact JSON-serializable view fed to the LLM stages."""
    return {
        "components": [
            {
                "id": n.id, "label": n.label, "type": n.type,
                "software": n.software, "hardware": n.hardware,
            }
            for n in graph.nodes
        ],
        "channels": [
            {
                "id": e.id, "from": e.source, "to": e.target, "label": e.label,
                "tech": e.tech or "unspecified",
                "interface": e.iface or "unspecified",
            }
            for e in graph.edges
        ],
    }
