"""
Threat Modeler — a UxV (unmanned vehicle) threat-modeling engine.

A modular Python re-implementation of the *threat-modeling* stage of
DefenseWeaver (arXiv:2504.18083, "Automating Function-Level TARA for
Automotive Full-Lifecycle Security"), ported to the UxV domain.

This package produces DefenseWeaver-style **attack trees** only. Risk
assessment / feasibility / risk-level (paper §IV-C3) is out of scope by
design (see README §"Agreed design decisions", Mod 2).

The code is split into single-responsibility modules so the *deterministic
core* can be unit-tested in isolation (no network, no LLM):

    dfd          Node / Edge / SystemModel  core DFD data model
    graph        build_engine_graph(...)   config-injected directed graph
                 all_simple_paths(...)     entry->endpoint acyclic paths (DFS)
                 build_atoms(...)          atom decomposition (paper §IV-B2)
    openxsampp   generate_openxsampp(...)  deterministic OpenXSAM++ XML
                 parse_openxsampp(...)     OpenXSAM++ XML -> (SystemModel, config)
    config_schema NODE_FIELDS/EDGE_FIELDS  §IV-B1 provenance-tagged config fields
    render       layout(tree)/render_tree_svg(tree)   SVG (+ optional PNG)

The *LLM stages* (non-deterministic, paper §IV-C) live in:

    models       MODELS catalog (anthropic / openai-compatible / ollama)
    llm          call_claude / call_openai / call_ollama / call_and_parse
    attack_rag   Attack-RAG client (per-component TTP/CVE/CWE grounding)
    stages       rag_enrich_components / derive_scenarios /
                 construct_subtree / assemble (AND/OR tree, no SEQ)
    pipeline     run_pipeline(...)         end-to-end orchestration
    cli          command-line entry point

Only the deterministic core is reproducible; the four LLM stages are
non-deterministic (the paper reports no reproducibility figures either).
The OpenXSAM++ serialization is a *documented reconstruction* of the
original OpenXSAM XSD skeleton plus the §IV-B1 additions — the paper does
not publish a complete XSD. Blank fields are emitted as ``unspecified``;
nothing is fabricated.
"""

__version__ = "0.2.0"

from .dfd import Node, Edge, SystemModel
from .graph import (
    build_engine_graph,
    all_simple_paths,
    scenario_paths,
    build_atoms,
    EngineGraph,
    Atom,
)
from .openxsampp import generate_openxsampp, parse_openxsampp
from .models import MODELS, DEFAULT_MODEL, DEFAULT_PROVIDER, is_known_model
from .validator import validate_attack_tree, ValidationIssue

__all__ = [
    "Node",
    "Edge",
    "SystemModel",
    "build_engine_graph",
    "all_simple_paths",
    "scenario_paths",
    "build_atoms",
    "EngineGraph",
    "Atom",
    "generate_openxsampp",
    "parse_openxsampp",
    "MODELS",
    "DEFAULT_MODEL",
    "DEFAULT_PROVIDER",
    "is_known_model",
    "validate_attack_tree",
    "ValidationIssue",
]
