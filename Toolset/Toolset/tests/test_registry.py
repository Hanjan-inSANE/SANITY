from pathlib import Path
import json
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from toolset_core.registry import ToolRegistry, validate_descriptor


class RegistryTests(unittest.TestCase):
    def test_p0_registry_loads_required_tools(self) -> None:
        registry = ToolRegistry.load(ROOT / "registry" / "tools.yaml")
        tool_ids = {tool["tool_id"] for tool in registry.list_tools(priority="P0")}
        required = {
            "cmake",
            "make",
            "ninja",
            "ctest",
            "pytest",
            "aflpp",
            "libfuzzer",
            "gdb",
            "strace",
            "asan",
            "ubsan",
            "gcov",
            "llvm_cov",
            "git_apply",
            "toolset_reporter",
        }
        self.assertTrue(required.issubset(tool_ids))

    def test_invalid_descriptor_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validate_descriptor({"tool_id": "bad", "kind": "fuzzer"})

    def test_list_tools_filters_by_target_and_kind(self) -> None:
        registry = ToolRegistry.load(ROOT / "registry" / "tools.yaml")
        fuzzers = registry.list_tools(kind="fuzzer", target="c", priority="P0")
        self.assertEqual({"aflpp", "libfuzzer"}, {tool["tool_id"] for tool in fuzzers})

    def test_probe_uses_alias_config(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "tests") as tmp:
            config = Path(tmp) / "toolset.local.json"
            config.write_text(json.dumps({"tool_aliases": {"python": sys.executable}}), encoding="utf-8")
            registry = ToolRegistry.load(ROOT / "registry" / "tools.yaml")
            probe = registry.probe("pytest", config_path=config)
            self.assertEqual(probe["resolved_command"][0], sys.executable)


if __name__ == "__main__":
    unittest.main()
