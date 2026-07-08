from pathlib import Path
import json
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from toolset_core.executor import ToolExecutor
from toolset_core.policy import validate_argv


class ExecutorPolicyTests(unittest.TestCase):
    def test_raw_shell_string_is_rejected(self) -> None:
        with self.assertRaises(TypeError):
            validate_argv("echo unsafe")  # type: ignore[arg-type]

    def test_executor_captures_stdout_and_ledger(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "tests") as tmp:
            executor = ToolExecutor(Path(tmp))
            result = executor.run(
                "python",
                "unit_test",
                [sys.executable, "-c", "print('ok')"],
                trace_id="trace-unit",
            )
            self.assertEqual(result["status"], "success")
            stdout_path = executor.artifacts.ref_to_path(result["diagnostics"]["stdout_ref"])
            self.assertEqual(stdout_path.read_text(encoding="utf-8").strip(), "ok")
            events = [json.loads(line) for line in executor.ledger.path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(events[0]["trace_id"], "trace-unit")
            self.assertEqual(events[0]["status"], "success")

    def test_missing_command_is_structured(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "tests") as tmp:
            executor = ToolExecutor(Path(tmp))
            result = executor.run(
                "missing_tool",
                "probe",
                ["definitely-not-a-real-toolset-command-xyz"],
                trace_id="trace-missing",
            )
            self.assertEqual(result["status"], "missing")
            self.assertEqual(result["diagnostics"]["error_type"], "MissingExecutable")

    def test_executor_uses_tool_alias_config(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "tests") as tmp:
            root = Path(tmp)
            config = root / "toolset.local.json"
            config.write_text(json.dumps({"tool_aliases": {"alias-python": sys.executable}}), encoding="utf-8")
            executor = ToolExecutor(root, config_path=config)
            result = executor.run(
                "alias-python",
                "unit_test",
                ["alias-python", "-c", "print('alias-ok')"],
                trace_id="trace-alias",
            )
            self.assertEqual(result["status"], "success")
            self.assertEqual(result["diagnostics"]["resolved_command"][0], sys.executable)


if __name__ == "__main__":
    unittest.main()
