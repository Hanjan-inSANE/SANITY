from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

from ..executor import ToolExecutor
from ..policy import validate_argv


def run_sanitizer(
    executor: ToolExecutor,
    sanitizer: str,
    target_cmd: list[str],
    trace_id: str | None = None,
    timeout_sec: int = 300,
) -> dict[str, Any]:
    if executor is None:
        raise ValueError("executor is required")
    if sanitizer not in {"asan", "ubsan", "msan", "tsan", "valgrind"}:
        raise ValueError("unsupported sanitizer")
    argv = validate_argv(target_cmd)
    trace_id = trace_id or f"{sanitizer}-{uuid4().hex}"
    env = {
        "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=1",
        "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
    }
    if sanitizer == "valgrind":
        argv = ["valgrind", "--error-exitcode=99", "--leak-check=full", *argv]
        tool_id = "valgrind"
    else:
        tool_id = sanitizer
    result = executor.run(tool_id, "memory_check", argv, cwd=executor.workspace_root, env=env, timeout_sec=timeout_sec, trace_id=trace_id)
    finding = result["status"] == "failure"
    payload = {
        "artifact_type": "SanitizerReport",
        "report_id": trace_id,
        "sanitizer": sanitizer,
        "finding_ref": result["diagnostics"].get("stderr_ref") if finding else None,
        "summary": "finding observed" if finding else "no sanitizer finding observed",
        "status": result["status"],
        "log_refs": result["artifact_refs"],
    }
    record = executor.artifacts.write_text(
        f"sanitizer/{trace_id}.json",
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
    )
    result["artifact_refs"].append(record.ref)
    result["diagnostics"]["sanitizer_report_ref"] = record.ref
    result["diagnostics"]["finding_observed"] = finding
    return result
