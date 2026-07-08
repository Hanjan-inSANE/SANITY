from __future__ import annotations

from pathlib import Path
import json
from uuid import uuid4

from ..executor import ToolExecutor
from ..policy import validate_argv


def trace_runtime(
    executor: ToolExecutor,
    target_cmd: list[str],
    trace_id: str | None = None,
    timeout_sec: int = 300,
    extra_args: list[str] | None = None,
) -> dict:
    if executor is None:
        raise ValueError("executor is required")
    argv = validate_argv(target_cmd)
    trace_id = trace_id or f"strace-{uuid4().hex}"
    trace_log = executor.artifacts.resolve(f"trace/{trace_id}.strace.txt")
    command = ["strace", "-f", "-o", str(trace_log), *(extra_args or []), *argv]
    result = executor.run(
        "strace",
        "runtime_trace",
        command,
        cwd=executor.workspace_root,
        timeout_sec=timeout_sec,
        trace_id=trace_id,
        extra_artifact_paths=[trace_log],
    )
    if trace_log.exists():
        log_record = executor.artifacts.copy_file(trace_log, f"trace/{trace_id}.strace.txt")
    else:
        log_record = executor.artifacts.write_text(f"trace/{trace_id}.strace.txt", "")
    payload = {
        "artifact_type": "RuntimeTrace",
        "trace_id": trace_id,
        "tool_id": "strace",
        "syscall_log_ref": log_record.ref,
        "status": result["status"],
    }
    record = executor.artifacts.write_text(
        f"trace/{trace_id}.json",
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
    )
    result["artifact_refs"].extend([log_record.ref, record.ref])
    result["diagnostics"]["runtime_trace_ref"] = record.ref
    result["diagnostics"]["syscall_log_ref"] = log_record.ref
    return result
