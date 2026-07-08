import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threat_modeler.graph import build_engine_graph, scenario_paths
from threat_modeler.openxsampp import parse_openxsampp
from threat_modeler.validator import validate_attack_tree


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OXPP = os.path.join(ROOT, "example1_px4_quad.openxsampp.xml")


class TestAttackTreeValidator(unittest.TestCase):
    """Trees use only objective / logic(AND|OR) / method nodes. Order is
    expressed by parent/child nesting — there is no SEQ node and no
    single-child-root rule, so the validator no longer checks for those.
    Method leaves must cite a concrete evidence id (CVE/CWE/ATT&CK/SPARTA)."""

    def setUp(self):
        with open(OXPP, encoding="utf-8") as fh:
            model, config = parse_openxsampp(fh.read())
        self.graph = build_engine_graph(model, config)
        self.entry = "9e17bb96-022e-e1fd-f9c2-84de246c564f"      # Ground Control Station
        self.endpoint = "8530fced-36d2-d3b3-c848-5bbdf0ad822f"   # ESC / Motor Controller
        self.path = scenario_paths(self.graph, [self.entry], self.endpoint)[0]
        self.ctx = self._context(self.path)
        self.entry_label = self.graph.by_id[self.entry].label
        self.endpoint_label = self.graph.by_id[self.endpoint].label

    def _context(self, path):
        components = [{"id": nid, "label": self.graph.by_id[nid].label} for nid in path]
        channels = []
        for i in range(len(path) - 1):
            src, dst = path[i], path[i + 1]
            ch = next(ch for to, ch in self.graph.adj[src] if to == dst)
            channels.append({"id": ch.id, "label": ch.label})
        return {
            "components": components,
            "channels": channels,
            "knownComponents": [{"id": n.id, "label": n.label} for n in self.graph.nodes],
            "knownChannels": [{"id": e.id, "label": e.label} for e in self.graph.edges],
        }

    def _valid_tree(self, leaf=None):
        # Uniform nodes (no 'kind'): root is the objective, AND/OR on parents,
        # leaves grounded by evidence + attack_context; order via nesting.
        leaf = leaf or {
            "summary": "Write valid command frames to the modeled channel (T0831)",
            "attack_context": "The channel accepts unauthenticated command frames.",
            "evidence": [{"id": "T0831", "note": "control manipulation"}],
            "dfd_component": self.endpoint_label,
        }
        return {
            "summary": "Destabilize the endpoint through the modeled path",
            "logic": "AND",
            "children": [{
                "summary": "Reach the endpoint then actuate",
                "logic": "AND",
                "children": [
                    {
                        "summary": "Obtain output capability at the entry component",
                        "logic": "OR",
                        "dfd_component": self.entry_label,
                        "children": [
                            leaf,
                            {"summary": "Use an existing authorized output path (T0836)",
                             "attack_context": "Abuse an already-authorized output path.",
                             "dfd_component": self.entry_label},
                        ],
                    },
                    {"summary": "Deliver the malicious effect to the endpoint (T0831)",
                     "attack_context": "Relay the crafted effect to the endpoint.",
                     "dfd_component": self.endpoint_label},
                ],
            }],
        }

    def _run(self, tree):
        return validate_attack_tree(tree, self.ctx, [self.entry_label], [self.endpoint_label])

    def test_valid_and_or_tree_has_no_errors(self):
        issues = self._run(self._valid_tree())
        self.assertFalse([i for i in issues if i.severity == "err"], issues)

    def test_flat_root_children_are_allowed(self):
        # Multiple root children are permitted (no SEQ single-child rule).
        tree = {
            "summary": "root objective", "logic": "AND", "children": [
                {"summary": "branch a (T0831)", "attack_context": "x", "dfd_component": self.entry_label},
                {"summary": "branch b (T0836)", "attack_context": "x", "dfd_component": self.endpoint_label},
            ],
        }
        issues = self._run(tree)
        codes = {i.code for i in issues}
        self.assertNotIn("root_child_count", codes)
        self.assertNotIn("root_chain", codes)

    def test_unrelated_branch_outside_path_is_flagged(self):
        tree = self._valid_tree({
            "summary": "Use CRSF/SBUS path through RC Receiver",
            "attack_context": "x",
        })
        codes = {i.code for i in self._run(tree)}
        self.assertTrue({"outside_component_label", "outside_channel_label"} & codes)

    def test_speculative_rce_requires_concrete_cve(self):
        # A speculative RCE leaf without a concrete CVE is flagged...
        codes = {i.code for i in self._run(self._valid_tree({
            "summary": "Exploit CVE-class RCE in parser", "attack_context": "x"}))}
        self.assertIn("speculative_leaf", codes)

        # ...and citing a concrete CVE clears it.
        fixed = {i.code for i in self._run(self._valid_tree({
            "summary": "Exploit CVE-2024-1234 RCE in parser", "attack_context": "x"}))}
        self.assertNotIn("speculative_leaf", fixed)

    def test_leaf_without_evidence_is_flagged(self):
        # A bare leaf with no evidence id is flagged (Req 4)...
        codes = {i.code for i in self._run(self._valid_tree({
            "summary": "Do something to the endpoint", "attack_context": "x",
            "dfd_component": self.endpoint_label}))}
        self.assertIn("leaf_without_evidence", codes)

        # ...and citing an ATT&CK/CVE id in the summary clears it (fallback).
        fixed = {i.code for i in self._run(self._valid_tree({
            "summary": "Send crafted setpoint frames (T0831)", "attack_context": "x",
            "dfd_component": self.endpoint_label}))}
        self.assertNotIn("leaf_without_evidence", fixed)

    def test_structured_evidence_and_context_ground_a_leaf(self):
        # A clean summary grounded by the structured evidence + attack_context
        # fields (the intended shape) is fully grounded.
        codes = {i.code for i in self._run(self._valid_tree({
            "summary": "Inject crafted setpoint frames",
            "dfd_component": self.endpoint_label,
            "attack_context": "The ESC accepts unauthenticated PWM setpoints over "
                              "the modeled channel; crafted frames override motor output.",
            "evidence": [{"id": "T0831", "note": "manipulation of control to drive actuators"}],
        }))}
        self.assertNotIn("leaf_without_evidence", codes)
        self.assertNotIn("leaf_without_context", codes)

    def test_weak_or_is_flagged(self):
        tree = self._valid_tree()
        # replace the OR node's children with a single child
        or_node = tree["children"][0]["children"][0]
        or_node["children"] = [{"summary": "lonely (T0831)", "attack_context": "x",
                                "dfd_component": self.entry_label}]
        self.assertIn("weak_or", {i.code for i in self._run(tree)})


if __name__ == "__main__":
    unittest.main(verbosity=2)
