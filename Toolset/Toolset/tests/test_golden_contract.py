from pathlib import Path
import os
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from toolset_mcp import server


FIXTURE = ROOT / "tests" / "fixtures" / "c_buffer_overflow"


class GoldenContractTests(unittest.TestCase):
    def test_fixture_contains_vulnerable_target_and_patch(self) -> None:
        self.assertTrue((FIXTURE / "CMakeLists.txt").exists())
        self.assertTrue((FIXTURE / "vuln.c").exists())
        self.assertTrue((FIXTURE / "crash_input.txt").exists())
        self.assertTrue((FIXTURE / "fix.patch").exists())

    @unittest.skipUnless(os.environ.get("TOOLSET_INTEGRATION") == "1", "set TOOLSET_INTEGRATION=1 for external C toolchain test")
    def test_c_buffer_overflow_integration_when_toolchain_exists(self) -> None:
        cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        if cc is None:
            self.skipTest("no C compiler found")
        with tempfile.TemporaryDirectory(dir=ROOT / "tests") as tmp:
            workspace = Path(tmp)
            shutil.copytree(FIXTURE, workspace, dirs_exist_ok=True)
            binary = workspace / ("vuln.exe" if sys.platform.startswith("win") else "vuln")
            build = server.build(
                str(workspace),
                build_system="custom",
                source_dir=".",
                build_dir=".",
                trace_id="golden-build",
            )
            self.assertIn(build["status"], {"success", "failure", "missing"})
            compile_result = server.static_scan(
                str(workspace),
                "cppcheck",
                [cc, "-g", "-fsanitize=address", "-o", str(binary), str(workspace / "vuln.c")],
                trace_id="golden-compile",
            )
            self.assertEqual(compile_result["status"], "success")
            baseline = server.reproduce_pov(
                str(workspace),
                [str(binary)],
                input_blob=str(workspace / "crash_input.txt"),
                trace_id="golden-baseline",
            )
            self.assertTrue(baseline["diagnostics"]["reproduced"])


if __name__ == "__main__":
    unittest.main()
