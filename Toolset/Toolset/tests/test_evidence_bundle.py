from pathlib import Path
import json
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from toolset_core.executor import ToolExecutor


class EvidenceBundleTests(unittest.TestCase):
    def test_export_bundle_includes_artifact_hashes(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "tests") as tmp:
            executor = ToolExecutor(Path(tmp))
            result = executor.run("python", "unit_test", [sys.executable, "-c", "print('evidence')"], trace_id="trace-evidence")
            bundle = executor.ledger.export_bundle(
                executor.artifacts,
                trace_id="trace-evidence",
                verdict="defense_verified",
                test_result_refs=result["artifact_refs"],
            )
            bundle_path = executor.artifacts.ref_to_path(bundle["bundle_ref"])
            payload = json.loads(bundle_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["verdict"], "defense_verified")
            self.assertGreaterEqual(len(payload["artifact_hashes"]), 2)


if __name__ == "__main__":
    unittest.main()
