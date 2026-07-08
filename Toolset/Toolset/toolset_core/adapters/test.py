from __future__ import annotations

from pathlib import Path
import sys
from typing import Any
from uuid import uuid4

from ..executor import ToolExecutor
from ..policy import ensure_path_inside


def run_tests(
    executor: ToolExecutor,
    test_runner: str,
    test_dir: str | Path | None = None,
    build_dir: str | Path | None = None,
    trace_id: str | None = None,
    timeout_sec: int = 600,
    extra_args: list[str] | None = None,
) -> dict[str, Any]:
    if executor is None:
        raise ValueError("executor is required")
    if not test_runner:
        raise ValueError("test_runner is required")
    trace_id = trace_id or f"test-{uuid4().hex}"
    extra_args = extra_args or []

    if test_runner == "ctest":
        if not build_dir:
            raise ValueError("build_dir is required for ctest")
        build_path = Path(build_dir).resolve() if Path(build_dir).is_absolute() else executor.workspace_root / build_dir
        build_path = ensure_path_inside(build_path, executor.workspace_root)
        argv = ["ctest", "--test-dir", str(build_path), "--output-on-failure", *extra_args]
        result = executor.run("ctest", "regression_test", argv, cwd=executor.workspace_root, timeout_sec=timeout_sec, trace_id=trace_id)
        return _with_test_artifact(executor, result, test_runner)

    if test_runner == "pytest":
        path = Path(test_dir or ".")
        test_path = path.resolve() if path.is_absolute() else executor.workspace_root / path
        test_path = ensure_path_inside(test_path, executor.workspace_root)
        argv = [sys.executable, "-m", "pytest", str(test_path), *extra_args]
        result = executor.run("pytest", "regression_test", argv, cwd=executor.workspace_root, timeout_sec=timeout_sec, trace_id=trace_id)
        return _with_test_artifact(executor, result, test_runner)

    if test_runner == "custom":
        if not extra_args:
            raise ValueError("extra_args must contain custom argv")
        result = executor.run("custom_test", "regression_test", extra_args, cwd=executor.workspace_root, timeout_sec=timeout_sec, trace_id=trace_id)
        return _with_test_artifact(executor, result, test_runner)

    raise ValueError(f"unsupported test_runner: {test_runner}")


def _with_test_artifact(executor: ToolExecutor, result: dict[str, Any], test_runner: str) -> dict[str, Any]:
    import json

    payload = {
        "artifact_type": "TestResult",
        "test_result_id": result["trace_id"],
        "tool_id": test_runner,
        "passed": result["status"] == "success",
        "failed_tests": [] if result["status"] == "success" else ["see logs"],
        "log_refs": result["artifact_refs"],
        "status": result["status"],
    }
    record = executor.artifacts.write_text(
        f"tests/{result['trace_id']}.json",
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
    )
    result["artifact_refs"].append(record.ref)
    result["diagnostics"]["test_result_ref"] = record.ref
    return result
