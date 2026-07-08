"""
Core DFD data model shared across the engine.

These deterministic dataclasses are the common currency of the pipeline: the
OpenXSAM++ loader produces them, and the graph builder, path finder, and LLM
stages all consume them. They intentionally carry no parsing or provider logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class Node:
    guid: str
    type: str          # process | external | store | element
    label: str
    x: float = 0.0
    y: float = 0.0
    w: float = 150.0
    h: float = 60.0


@dataclass
class Edge:
    guid: str
    label: str
    source: str
    target: str


@dataclass
class SystemModel:
    nodes: List[Node] = field(default_factory=list)
    edges: List[Edge] = field(default_factory=list)

    def by_id(self) -> Dict[str, Node]:
        return {n.guid: n for n in self.nodes}
