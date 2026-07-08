from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from toolset_mcp import server


class McpContractTests(unittest.TestCase):
    def test_list_tools_common_response_shape(self) -> None:
        result = server.list_tools(target="c")
        self.assertTrue(result["ok"])
        self.assertEqual(result["tool_id"], "toolset.list_tools")
        self.assertIn("tools", result["diagnostics"])

    def test_create_workspace_and_detect_target(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "tests") as tmp:
            ws = server.create_workspace(base_dir=tmp, workspace_id="contract-ws")
            self.assertEqual(ws["status"], "success")
            workspace_root = ws["diagnostics"]["workspace_root"]
            Path(workspace_root, "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
            detected = server.detect_target(workspace_root)
            self.assertEqual(detected["status"], "success")
            self.assertEqual(detected["diagnostics"]["target_profile"]["language"], "c")

    def test_compare_baseline_gate_logic(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "tests") as tmp:
            result = server.compare_baseline(
                tmp,
                baseline_pov_reproduces=True,
                patched_pov_blocked=True,
                patched_build_success=True,
                regression_tests_pass=True,
                no_new_sanitizer_finding_on_replay=True,
                evidence_bundle_complete=True,
                trace_id="trace-compare",
            )
            self.assertEqual(result["diagnostics"]["verdict"], "defense_verified")

    def test_reproduce_pov_uses_structured_result(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "tests") as tmp:
            result = server.reproduce_pov(
                tmp,
                [sys.executable, "-c", "import sys; sys.exit(2)"],
                trace_id="trace-pov",
            )
            self.assertEqual(result["status"], "failure")
            self.assertTrue(result["diagnostics"]["reproduced"])
            self.assertIn("pov_ref", result["diagnostics"])

    def test_export_evidence_and_generate_report(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "tests") as tmp:
            compare = server.compare_baseline(
                tmp,
                baseline_pov_reproduces=True,
                patched_pov_blocked=True,
                patched_build_success=True,
                regression_tests_pass=True,
                no_new_sanitizer_finding_on_replay=True,
                evidence_bundle_complete=True,
                trace_id="trace-report",
            )
            exported = server.export_evidence(
                tmp,
                trace_id="trace-report",
                verdict="defense_verified",
                baseline_result_ref=compare["diagnostics"]["comparison_ref"],
            )
            self.assertEqual(exported["status"], "success")
            report = server.generate_report(tmp, exported["diagnostics"]["bundle_ref"], trace_id="trace-report-md")
            self.assertEqual(report["status"], "success")
            self.assertIn("report_ref", report["diagnostics"])


if __name__ == "__main__":
    unittest.main()
