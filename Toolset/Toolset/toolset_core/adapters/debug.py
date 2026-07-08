from __future__ import annotations

from pathlib import Path
import json
from typing import Any
from uuid import uuid4

from ..executor import ToolExecutor
from ..policy import ensure_path_inside, validate_argv


def debug_gdb(
    executor: ToolExecutor,
    target_cmd: list[str],
    input_blob: str | Path | None = None,
    trace_id: str | None = None,
    timeout_sec: int = 300,
) -> dict[str, Any]:
    if executor is None:
        raise ValueError("executor is required")
    argv = validate_argv(target_cmd)
    if not argv:
        raise ValueError("target_cmd is required")
    trace_id = trace_id or f"gdb-{uuid4().hex}"
    input_path = None
    if input_blob:
        input_path = Path(input_blob).resolve() if Path(input_blob).is_absolute() else executor.workspace_root / input_blob
        input_path = ensure_path_inside(input_path, executor.workspace_root)
    run_line = "run"
    if input_path:
        run_line = f"run < {input_path}"
    script = "\n".join(
        [
            "set pagination off",
            "set confirm off",
            run_line,
            "bt full",
            "info registers",
            "quit",
            "",
        ]
    )
    script_record = executor.artifacts.write_text(f"debug/{trace_id}.gdb", script)
    command = ["gdb", "--batch", "-x", str(script_record.path), "--args", *argv]
    result = executor.run("gdb", "debug", command, cwd=executor.workspace_root, timeout_sec=timeout_sec, trace_id=trace_id)
    payload = {
        "artifact_type": "DebugTrace",
        "trace_id": trace_id,
        "tool_id": "gdb",
        "pov_ref": str(input_path or ""),
        "stacktrace_ref": result["diagnostics"].get("stdout_ref"),
        "registers_ref": result["diagnostics"].get("stdout_ref"),
        "script_ref": script_record.ref,
        "status": result["status"],
    }
    record = executor.artifacts.write_text(
        f"debug/{trace_id}.json",
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
    )
    result["artifact_refs"].extend([script_record.ref, record.ref])
    result["diagnostics"]["debug_trace_ref"] = record.ref
    return result
