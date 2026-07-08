from __future__ import annotations

import json
import re
from pathlib import Path
import sys
from typing import Any
from uuid import uuid4

TOOLSET_ROOT = Path(__file__).resolve().parents[1]
if str(TOOLSET_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOLSET_ROOT))

from toolset_core import ToolExecutor, ToolRegistry, create_workspace as core_create_workspace
from toolset_core.adapters.build import build_target
from toolset_core.adapters.compare import compare_baseline as compare_baseline_adapter
from toolset_core.adapters.coverage import measure_coverage as measure_coverage_adapter
from toolset_core.adapters.debug import debug_gdb as debug_gdb_adapter
from toolset_core.adapters.fuzz import collect_findings as collect_findings_adapter
from toolset_core.adapters.fuzz import start_fuzz as start_fuzz_adapter
from toolset_core.adapters.patch import apply_unified_diff
from toolset_core.adapters.replay import reproduce_pov as reproduce_pov_adapter
from toolset_core.adapters.report import generate_report as generate_report_adapter
from toolset_core.adapters.sanitizer import run_sanitizer as run_sanitizer_adapter
from toolset_core.adapters.static_analysis import static_scan as static_scan_adapter
from toolset_core.adapters.test import run_tests as run_tests_adapter
from toolset_core.adapters.trace import trace_runtime as trace_runtime_adapter
from toolset_core.artifacts import ArtifactStore
from toolset_core.evidence import EvidenceLedger
from toolset_core.policy import ensure_path_inside
from .models import common_response, exception_response


def _registry() -> ToolRegistry:
    return ToolRegistry.load(TOOLSET_ROOT / "registry" / "tools.yaml")


def _executor(workspace_root: str | Path) -> ToolExecutor:
    root = Path(workspace_root).resolve()
    return ToolExecutor(
        root,
        artifact_store=ArtifactStore(root / "artifacts"),
        ledger=EvidenceLedger(root / "artifacts" / "evidence" / "ledger.jsonl"),
    )


def list_tools(kind: str | None = None, target: str | None = None, phase: str | None = None, priority: str | None = "P0") -> dict[str, Any]:
    try:
        tools = _registry().list_tools(kind=kind, target=target, phase=phase, priority=priority)
        return common_response(
            "toolset.list_tools",
            "success",
            f"{len(tools)} tools matched",
            artifact_refs=[],
            diagnostics={"duration_ms": 0, "exit_code": 0, "tools": tools},
        )
    except Exception as exc:  # noqa: BLE001
        return exception_response("toolset.list_tools", exc)


def probe_tool(tool_id: str, workspace_root: str | None = None, config_path: str | None = None) -> dict[str, Any]:
    try:
        probe = _registry().probe(tool_id, config_path=config_path)
        status = "success" if probe["availability"] == "available" else "missing"
        trace_id = f"probe-{uuid4().hex}"
        if workspace_root:
            executor = _executor(workspace_root)
            descriptor = _registry().get(tool_id)
            command = descriptor["availability_probe"]["command"]
            if command != ["internal"]:
                return executor.run(tool_id, "availability_probe", command, trace_id=trace_id, timeout_sec=30)
        return common_response(
            "toolset.probe_tool",
            status,
            f"{tool_id} availability: {probe['availability']}",
            trace_id=trace_id,
            diagnostics={"duration_ms": 0, "exit_code": 0 if status == "success" else None, **probe},
        )
    except Exception as exc:  # noqa: BLE001
        return exception_response("toolset.probe_tool", exc)


def create_workspace(base_dir: str | None = None, workspace_id: str | None = None) -> dict[str, Any]:
    try:
        workspace = core_create_workspace(base_dir=base_dir, workspace_id=workspace_id)
        payload = {
            "artifact_type": "ChallengeBundle",
            "artifact_id": workspace.workspace_id,
            "workspace_id": workspace.workspace_id,
            "workspace_root": str(workspace.root),
            "artifact_root": str(workspace.artifacts.root),
            "ledger_path": str(workspace.ledger.path),
        }
        record = workspace.artifacts.write_text("workspace.json", json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
        return common_response(
            "toolset.create_workspace",
            "success",
            f"created workspace {workspace.workspace_id}",
            trace_id=f"workspace-{workspace.workspace_id}",
            artifact_refs=[record.ref],
            diagnostics={"duration_ms": 0, "exit_code": 0, **payload, "workspace_ref": record.ref},
        )
    except Exception as exc:  # noqa: BLE001
        return exception_response("toolset.create_workspace", exc)


def detect_target(workspace_root: str) -> dict[str, Any]:
    try:
        root = Path(workspace_root).resolve()
        executor = _executor(root)
        profile = _detect_profile(root)
        record = executor.artifacts.write_text(
            f"target/{profile['target_profile_id']}.json",
            json.dumps(profile, ensure_ascii=False, indent=2, sort_keys=True),
        )
        executor.ledger.append(
            {
                "trace_id": profile["target_profile_id"],
                "event_type": "tool_invocation",
                "tool_id": "toolset.detect_target",
                "phase": "target_triage",
                "workspace_id": root.name,
                "command": [],
                "cwd": str(root),
                "env_redacted": {},
                "duration_ms": 0,
                "exit_code": 0,
                "status": "success",
                "produced_artifacts": [record.ref],
                "artifact_hashes": {record.ref: record.sha256},
                "summary": "target profile detected",
            }
        )
        return common_response(
            "toolset.detect_target",
            "success",
            "target profile detected",
            trace_id=profile["target_profile_id"],
            artifact_refs=[record.ref],
            diagnostics={"duration_ms": 0, "exit_code": 0, "target_profile": profile, "target_profile_ref": record.ref},
        )
    except Exception as exc:  # noqa: BLE001
        return exception_response("toolset.detect_target", exc)


def build(
    workspace_root: str,
    build_system: str = "auto",
    source_dir: str = ".",
    build_dir: str = "build",
    target: str | None = None,
    sanitizer: str | None = None,
    timeout_sec: int = 1200,
    extra_args: list[str] | None = None,
    trace_id: str | None = None,
) -> dict[str, Any]:
    try:
        return build_target(_executor(workspace_root), build_system, source_dir, build_dir, target, sanitizer, trace_id, timeout_sec, extra_args)
    except Exception as exc:  # noqa: BLE001
        return exception_response("toolset.build", exc, trace_id)


def run_tests(
    workspace_root: str,
    test_runner: str,
    test_dir: str | None = None,
    build_dir: str | None = None,
    timeout_sec: int = 600,
    extra_args: list[str] | None = None,
    trace_id: str | None = None,
) -> dict[str, Any]:
    try:
        return run_tests_adapter(_executor(workspace_root), test_runner, test_dir, build_dir, trace_id, timeout_sec, extra_args)
    except Exception as exc:  # noqa: BLE001
        return exception_response("toolset.run_tests", exc, trace_id)


def build_harness(
    workspace_root: str,
    harness_source: str | None = None,
    harness_path: str | None = None,
    entrypoint: str | None = None,
    input_format: str = "bytes",
    trace_id: str | None = None,
) -> dict[str, Any]:
    try:
        executor = _executor(workspace_root)
        trace_id = trace_id or f"harness-{uuid4().hex}"
        if harness_source:
            harness_record = executor.artifacts.write_text(f"harness/{trace_id}.c", harness_source)
        elif harness_path:
            source = Path(harness_path).resolve() if Path(harness_path).is_absolute() else Path(workspace_root).resolve() / harness_path
            source = ensure_path_inside(source, Path(workspace_root).resolve())
            harness_record = executor.artifacts.copy_file(source, f"harness/{trace_id}{source.suffix}")
        else:
            return executor.skipped("toolset.build_harness", trace_id, "no harness_source or harness_path provided")
        payload = {
            "artifact_type": "HarnessArtifact",
            "harness_id": trace_id,
            "entrypoint": entrypoint,
            "input_format": input_format,
            "harness_ref": harness_record.ref,
        }
        record = executor.artifacts.write_text(
            f"harness/{trace_id}.json",
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
        )
        executor.ledger.append(
            {
                "trace_id": trace_id,
                "event_type": "tool_invocation",
                "tool_id": "toolset.build_harness",
                "phase": "harness_build",
                "workspace_id": Path(workspace_root).resolve().name,
                "command": [],
                "cwd": str(Path(workspace_root).resolve()),
                "env_redacted": {},
                "duration_ms": 0,
                "exit_code": 0,
                "status": "success",
                "produced_artifacts": [harness_record.ref, record.ref],
                "artifact_hashes": {harness_record.ref: harness_record.sha256, record.ref: record.sha256},
                "summary": "harness registered",
            }
        )
        return common_response(
            "toolset.build_harness",
            "success",
            "harness registered",
            trace_id=trace_id,
            artifact_refs=[harness_record.ref, record.ref],
            diagnostics={"duration_ms": 0, "exit_code": 0, "harness_ref": harness_record.ref, "harness_artifact_ref": record.ref},
        )
    except Exception as exc:  # noqa: BLE001
        return exception_response("toolset.build_harness", exc, trace_id)


def start_fuzz(
    workspace_root: str,
    tool_id: str,
    target_cmd: list[str],
    seeds_dir: str,
    output_dir: str | None = None,
    timeout_sec: int = 3600,
    max_total_time: int | None = None,
    runs: int | None = None,
    extra_args: list[str] | None = None,
    trace_id: str | None = None,
) -> dict[str, Any]:
    try:
        return start_fuzz_adapter(_executor(workspace_root), tool_id, target_cmd, seeds_dir, output_dir, trace_id, timeout_sec, max_total_time, runs, extra_args)
    except Exception as exc:  # noqa: BLE001
        return exception_response("toolset.start_fuzz", exc, trace_id)


def collect_findings(workspace_root: str, fuzz_output_dir: str, trace_id: str | None = None) -> dict[str, Any]:
    try:
        return collect_findings_adapter(_executor(workspace_root), fuzz_output_dir, trace_id)
    except Exception as exc:  # noqa: BLE001
        return exception_response("toolset.collect_findings", exc, trace_id)


def reproduce_pov(
    workspace_root: str,
    target_cmd: list[str],
    input_blob: str | None = None,
    input_blob_ref: str | None = None,
    input_mode: str = "stdin",
    timeout_sec: int = 120,
    trace_id: str | None = None,
) -> dict[str, Any]:
    try:
        return reproduce_pov_adapter(_executor(workspace_root), target_cmd, input_blob, input_blob_ref, input_mode, trace_id, timeout_sec)
    except Exception as exc:  # noqa: BLE001
        return exception_response("toolset.reproduce_pov", exc, trace_id)


def debug_gdb(workspace_root: str, target_cmd: list[str], input_blob: str | None = None, timeout_sec: int = 300, trace_id: str | None = None) -> dict[str, Any]:
    try:
        return debug_gdb_adapter(_executor(workspace_root), target_cmd, input_blob, trace_id, timeout_sec)
    except Exception as exc:  # noqa: BLE001
        return exception_response("toolset.debug_gdb", exc, trace_id)


def trace_runtime(workspace_root: str, target_cmd: list[str], timeout_sec: int = 300, extra_args: list[str] | None = None, trace_id: str | None = None) -> dict[str, Any]:
    try:
        return trace_runtime_adapter(_executor(workspace_root), target_cmd, trace_id, timeout_sec, extra_args)
    except Exception as exc:  # noqa: BLE001
        return exception_response("toolset.trace_runtime", exc, trace_id)


def run_sanitizer(workspace_root: str, sanitizer: str, target_cmd: list[str], timeout_sec: int = 300, trace_id: str | None = None) -> dict[str, Any]:
    try:
        return run_sanitizer_adapter(_executor(workspace_root), sanitizer, target_cmd, trace_id, timeout_sec)
    except Exception as exc:  # noqa: BLE001
        return exception_response("toolset.run_sanitizer", exc, trace_id)


def measure_coverage(
    workspace_root: str,
    tool_id: str,
    target: str,
    profile_data: str | None = None,
    timeout_sec: int = 300,
    extra_args: list[str] | None = None,
    trace_id: str | None = None,
) -> dict[str, Any]:
    try:
        return measure_coverage_adapter(_executor(workspace_root), tool_id, target, profile_data, trace_id, timeout_sec, extra_args)
    except Exception as exc:  # noqa: BLE001
        return exception_response("toolset.measure_coverage", exc, trace_id)


def static_scan(workspace_root: str, tool_id: str, scan_cmd: list[str], timeout_sec: int = 600, trace_id: str | None = None) -> dict[str, Any]:
    try:
        return static_scan_adapter(_executor(workspace_root), tool_id, scan_cmd, trace_id, timeout_sec)
    except Exception as exc:  # noqa: BLE001
        return exception_response("toolset.static_scan", exc, trace_id)


def apply_patch(workspace_root: str, patch_text: str | None = None, patch_path: str | None = None, timeout_sec: int = 120, trace_id: str | None = None) -> dict[str, Any]:
    try:
        return apply_unified_diff(_executor(workspace_root), patch_text, patch_path, trace_id, timeout_sec)
    except Exception as exc:  # noqa: BLE001
        return exception_response("toolset.apply_patch", exc, trace_id)


def compare_baseline(
    workspace_root: str,
    baseline_pov_reproduces: bool,
    patched_pov_blocked: bool,
    patched_build_success: bool,
    regression_tests_pass: bool,
    no_new_sanitizer_finding_on_replay: bool,
    evidence_bundle_complete: bool,
    trace_id: str | None = None,
) -> dict[str, Any]:
    try:
        return compare_baseline_adapter(
            _executor(workspace_root),
            baseline_pov_reproduces,
            patched_pov_blocked,
            patched_build_success,
            regression_tests_pass,
            no_new_sanitizer_finding_on_replay,
            evidence_bundle_complete,
            trace_id,
        )
    except Exception as exc:  # noqa: BLE001
        return exception_response("toolset.compare_baseline", exc, trace_id)


def export_evidence(
    workspace_root: str,
    trace_id: str,
    verdict: str,
    pov_ref: str | None = None,
    patch_ref: str | None = None,
    baseline_result_ref: str | None = None,
    patched_result_ref: str | None = None,
    test_result_refs: list[str] | None = None,
    trace_refs: list[str] | None = None,
    coverage_refs: list[str] | None = None,
    bundle_id: str | None = None,
) -> dict[str, Any]:
    try:
        executor = _executor(workspace_root)
        bundle = executor.ledger.export_bundle(
            executor.artifacts,
            trace_id=trace_id,
            verdict=verdict,
            pov_ref=pov_ref,
            patch_ref=patch_ref,
            baseline_result_ref=baseline_result_ref,
            patched_result_ref=patched_result_ref,
            test_result_refs=test_result_refs,
            trace_refs=trace_refs,
            coverage_refs=coverage_refs,
            bundle_id=bundle_id,
        )
        return common_response(
            "toolset.export_evidence",
            "success",
            "evidence bundle exported",
            trace_id=trace_id,
            artifact_refs=[bundle["bundle_ref"]],
            diagnostics={"duration_ms": 0, "exit_code": 0, **bundle},
        )
    except Exception as exc:  # noqa: BLE001
        return exception_response("toolset.export_evidence", exc, trace_id)


def generate_report(workspace_root: str, bundle_ref: str, title: str = "DAH Toolset Defense Evidence Report", trace_id: str | None = None) -> dict[str, Any]:
    try:
        return generate_report_adapter(_executor(workspace_root), bundle_ref, trace_id, title)
    except Exception as exc:  # noqa: BLE001
        return exception_response("toolset.generate_report", exc, trace_id)


def _detect_profile(root: Path) -> dict[str, Any]:
    source_files = list(root.rglob("*.c")) + list(root.rglob("*.cc")) + list(root.rglob("*.cpp")) + list(root.rglob("*.cxx"))
    py_files = list(root.rglob("*.py"))
    java_files = list(root.rglob("*.java"))
    language = "unknown"
    if any(path.suffix == ".c" for path in source_files):
        language = "c"
    elif source_files:
        language = "cxx"
    elif py_files:
        language = "python"
    elif java_files:
        language = "java"

    build_system = "unknown"
    if (root / "CMakeLists.txt").exists():
        build_system = "cmake"
    elif (root / "build.ninja").exists():
        build_system = "ninja"
    elif (root / "Makefile").exists() or (root / "makefile").exists():
        build_system = "make"
    elif (root / "pyproject.toml").exists() or (root / "requirements.txt").exists():
        build_system = "python"
    elif (root / "pom.xml").exists():
        build_system = "maven"
    elif (root / "build.gradle").exists() or (root / "build.gradle.kts").exists():
        build_system = "gradle"

    security_relevant_files = [
        str(path.relative_to(root))
        for path in source_files[:100]
        if path.is_file() and not any(part in {".git", "artifacts", "build"} for part in path.parts)
    ]
    test_commands: list[list[str]] = []
    if build_system == "cmake":
        test_commands.append(["ctest", "--test-dir", "build", "--output-on-failure"])
    if language == "python":
        test_commands.append([sys.executable, "-m", "pytest", "."])

    return {
        "artifact_type": "TargetProfile",
        "target_profile_id": f"target-{uuid4().hex}",
        "language": language,
        "build_system": build_system,
        "runtime": "native" if language in {"c", "cxx"} else language,
        "entrypoints": [],
        "test_commands": test_commands,
        "security_relevant_files": security_relevant_files,
    }


def _fill_template(template, params):
    filled = []
    unresolved = set()
    for tok in template:
        m = re.fullmatch(r"\{(\w+)\}", tok)
        if m and m.group(1) in params:
            val = params[m.group(1)]
            if isinstance(val, (list, tuple)):
                filled.extend(str(x) for x in val)
            else:
                filled.append(str(val))
            continue

        def _rep(mm):
            key = mm.group(1)
            if key in params:
                return str(params[key])
            unresolved.add(key)
            return mm.group(0)

        filled.append(re.sub(r"\{(\w+)\}", _rep, tok))
    return filled, unresolved


def run_tool(
    workspace_root: str,
    tool_id: str,
    params: dict | None = None,
    extra_args: list[str] | None = None,
    output_paths: list[str] | None = None,
    timeout_sec: int | None = None,
    trace_id: str | None = None,
) -> dict[str, Any]:
    """Generic executor: run any registered tool by filling its command_template.

    argv-only, evidence-logged, workspace-contained. Placeholders in the tool's
    command_template are substituted from ``params``; files in ``output_paths``
    are captured as artifacts. Phase/timeout come from the registry descriptor."""
    try:
        descriptor = _registry().get(tool_id)
        if descriptor["execution"].get("mode") == "internal":
            return exception_response(
                "toolset.run_tool",
                ValueError(f"{tool_id} is an internal tool; use its dedicated MCP function"),
                trace_id,
            )
        params = {"toolset_root": str(TOOLSET_ROOT), **(params or {})}
        argv, unresolved = _fill_template(list(descriptor["execution"]["command_template"]), params)
        if extra_args:
            argv = argv + list(extra_args)
        if unresolved:
            return common_response(
                "toolset.run_tool",
                "failure",
                f"unresolved command placeholders: {sorted(unresolved)}",
                trace_id=trace_id or f"run-{uuid4().hex}",
                diagnostics={"duration_ms": 0, "exit_code": None, "tool_id": tool_id,
                             "argv": argv, "unresolved": sorted(unresolved)},
            )
        phase = (descriptor.get("phase") or ["run"])[0]
        timeout = int(timeout_sec or descriptor.get("timeout_sec_default") or 300)
        executor = _executor(workspace_root)
        resolved_outputs = []
        for op in (output_paths or []):
            path = Path(op)
            path = path if path.is_absolute() else Path(workspace_root).resolve() / op
            resolved_outputs.append(str(ensure_path_inside(path, Path(workspace_root).resolve())))
        return executor.run(
            tool_id, phase, argv,
            cwd=executor.workspace_root, timeout_sec=timeout,
            trace_id=trace_id, extra_artifact_paths=resolved_outputs,
        )
    except Exception as exc:  # noqa: BLE001
        return exception_response("toolset.run_tool", exc, trace_id)


try:
    from mcp.server.fastmcp import FastMCP  # type: ignore
except Exception:  # noqa: BLE001
    mcp = None
else:
    mcp = FastMCP("dah-toolset")
    for _fn in [
        list_tools,
        probe_tool,
        detect_target,
        create_workspace,
        build,
        run_tests,
        build_harness,
        start_fuzz,
        collect_findings,
        reproduce_pov,
        debug_gdb,
        trace_runtime,
        run_sanitizer,
        measure_coverage,
        static_scan,
        apply_patch,
        compare_baseline,
        export_evidence,
        generate_report,
        run_tool,
    ]:
        mcp.tool()(_fn)


if __name__ == "__main__":
    if mcp is None:
        print("MCP package is not installed; import toolset_mcp.server and call functions directly.", file=sys.stderr)
        raise SystemExit(2)
    mcp.run()
