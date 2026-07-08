"""
Quantitative, headless unit tests for the Threat Modeler deterministic core.

Run:  python -m unittest discover -s tests -v
      (from the DAH_TM_DEMO directory)

These tests import ONLY the deterministic modules — no `anthropic`, no
network — so they are fully reproducible. Where possible each assertion
is checked against an INDEPENDENT recomputation (per the reproducibility
requirement): simple-path counts are cross-checked against a naive
recursive DFS written separately from the module under test.
"""

import os
import sys
import unittest
import xml.etree.ElementTree as ET

# Make the package importable when run from the DAH_TM_DEMO directory.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threat_modeler.dfd import SystemModel, Node, Edge
from threat_modeler.graph import (
    build_engine_graph, all_simple_paths, scenario_paths, build_atoms, normalize_config,
)
from threat_modeler.openxsampp import generate_openxsampp, parse_openxsampp

import glob

# The project ships OpenXSAM++ examples (topology + config + layout in one
# file). Pick whichever is present.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_OXPP = sorted(glob.glob(os.path.join(_ROOT, "*.openxsampp.xml")))
EXAMPLE_OXPP = _OXPP[0] if _OXPP else None


# --- an independent reference implementation for cross-checking ------------

def ref_simple_paths(adj, start, goal, seen=None):
    """Naive recursive all-simple-paths, written independently of the
    module's iterative version, used purely as an oracle."""
    seen = seen or [start]
    if start == goal:
        return [list(seen)]
    out = []
    for nxt in adj.get(start, []):
        if nxt not in seen:
            out.extend(ref_simple_paths(adj, nxt, goal, seen + [nxt]))
    return out


def synthetic_model():
    """A small hand-built topology with a deliberate cycle (C<->D) so we can
    assert exact acyclic-path counts.

        A -> B -> C -> D -> F   (and B -> C alt, C <-> D cycle, C -> E)

    Nodes: A B C D E F.  Directed edges below.
    """
    nodes = [Node(guid=x, type="process", label=x) for x in "ABCDEF"]
    pairs = [
        ("A", "B"), ("B", "C"), ("A", "C"),   # two ways into C
        ("C", "D"), ("D", "C"),               # cycle C<->D
        ("D", "F"),
        ("C", "E"),                            # branch off to E (dead-ends)
    ]
    edges = [Edge(guid=f"{s}{t}", label=f"{s}->{t}", source=s, target=t) for s, t in pairs]
    return SystemModel(nodes=nodes, edges=edges)


class TestSimplePaths(unittest.TestCase):
    def setUp(self):
        self.graph = build_engine_graph(synthetic_model())
        # adjacency as {node: [neighbors]} for the reference oracle
        self.ref_adj = {}
        for e in self.graph.edges:
            self.ref_adj.setdefault(e.source, []).append(e.target)

    def test_paths_match_reference(self):
        # A -> F: expected acyclic paths (D->C->... would revisit C, excluded):
        #   A -> B -> C -> D -> F
        #   A -> C -> D -> F
        got = all_simple_paths(self.graph.adj, "A", "F")
        ref = ref_simple_paths(self.ref_adj, "A", "F")
        self.assertEqual(len(got), len(ref), "path count must match the oracle")
        self.assertEqual(
            sorted(tuple(p) for p in got),
            sorted(tuple(p) for p in ref),
            "path sets must be identical",
        )
        self.assertEqual(len(got), 2)

    def test_no_cycles_in_output(self):
        for p in all_simple_paths(self.graph.adj, "A", "F"):
            self.assertEqual(len(p), len(set(p)), "paths must be acyclic")

    def test_max_len_cap(self):
        # Cap length so the longer (4-node) path is excluded.
        short = all_simple_paths(self.graph.adj, "A", "F", max_len=3)
        self.assertTrue(all(len(p) <= 3 for p in short))
        self.assertIn(["A", "C", "D", "F"], all_simple_paths(self.graph.adj, "A", "F"))

    def test_scenario_paths_union(self):
        # Two entries (A and B) into endpoint F.
        paths = scenario_paths(self.graph, ["A", "B"], "F")
        ref = ref_simple_paths(self.ref_adj, "A", "F") + ref_simple_paths(self.ref_adj, "B", "F")
        self.assertEqual(len(paths), len(ref))


class TestAtoms(unittest.TestCase):
    def setUp(self):
        self.graph = build_engine_graph(synthetic_model())
        self.paths = scenario_paths(self.graph, ["A"], "F")

    def test_atom_invariant(self):
        atoms = build_atoms(self.graph, self.paths).atoms
        # Independent recomputation of the invariant:
        on_edges = set()
        on_nodes = set()
        for p in self.paths:
            on_nodes.update(p)
            for i in range(len(p) - 1):
                on_edges.add((p[i], p[i + 1]))
        end_nodes = {p[-1] for p in self.paths}

        propagate = [a for a in atoms if a.kind == "propagate"]
        terminal = [a for a in atoms if a.kind == "terminal"]

        # exactly one propagate atom per on-path directed edge
        self.assertEqual(len(propagate), len(on_edges))
        # exactly one terminal atom per endpoint node that has no on-path exit
        self.assertEqual(len(terminal), len(end_nodes))

    def test_each_atom_single_local_objective(self):
        atoms = build_atoms(self.graph, self.paths).atoms
        for a in atoms:
            if a.kind == "propagate":
                self.assertIsNotNone(a.exit_edge)
                self.assertIsNotNone(a.next_node)
            else:
                self.assertIsNone(a.exit_edge)


@unittest.skipIf(EXAMPLE_OXPP is None, "no OpenXSAM++ example present in project root")
class TestOpenXSAMpp(unittest.TestCase):
    def setUp(self):
        with open(EXAMPLE_OXPP, encoding="utf-8") as fh:
            self.model, self.config = parse_openxsampp(fh.read())

    def test_wellformed_and_unspecified(self):
        xml = generate_openxsampp(self.model, config={})  # no config -> all blank
        root = ET.fromstring(xml)  # must be well-formed
        comps = [e for e in root.iter() if e.tag.rsplit("}", 1)[-1] == "Component"]
        self.assertEqual(len(comps), len(self.model.nodes))
        self.assertIn("unspecified", xml)  # blank fields -> 'unspecified'

    def test_config_injection(self):
        cfg = normalize_config(self.config)
        # pick any concrete configured value and confirm it round-trips
        sample = None
        for fields in cfg.values():
            for k, v in fields.items():
                if k != "__custom" and isinstance(v, str) and v.strip():
                    sample = v.splitlines()[0]
                    break
            if sample:
                break
        self.assertIsNotNone(sample, "example should carry some config")
        xml = generate_openxsampp(self.model, self.config)
        self.assertIn(sample, xml)


class TestRender(unittest.TestCase):
    def test_layout_and_svg(self):
        from threat_modeler.render import layout, render_tree_svg
        tree = {
            "summary": "root objective", "logic": "OR", "children": [
                {"summary": "method one (T0831)", "attack_context": "x",
                 "evidence": [{"id": "T0831", "note": "x"}]},
                {"summary": "method two (T0836)", "attack_context": "x",
                 "evidence": [{"id": "T0836", "note": "x"}]},
            ],
        }
        lay = layout(tree)
        # constants are returned (the VG-scope-bug guard)
        self.assertTrue(all(v > 0 for v in (lay.NW, lay.NH, lay.VG)))
        self.assertIn("_x", tree)  # layout annotated in place
        svg = render_tree_svg(tree)
        root = ET.fromstring(svg)  # standalone SVG must parse
        self.assertEqual(root.tag.rsplit("}", 1)[-1], "svg")
        self.assertIn("root objective", svg)
        self.assertIn("k-root", svg)   # root styled distinctly
        self.assertIn("k-node", svg)   # non-root uniform nodes


if __name__ == "__main__":
    unittest.main(verbosity=2)
