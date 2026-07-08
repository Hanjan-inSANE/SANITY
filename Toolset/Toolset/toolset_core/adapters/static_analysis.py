from __future__ import annotations

from pathlib import Path
import json
from uuid import uuid4

from ..executor import ToolExecutor
from ..policy import validate_argv


def static_scan(
    executor: ToolExecutor,
    tool_id: str,
    scan_cmd: list[str],
    trace_id: str | None = None,
    timeout_sec: int = 600,
) -> dict:
    if executor is None:
        raise ValueError("executor is required")
    if tool_id not in {"semgrep", "codeql", "clang_tidy", "cppcheck", "bandit", "spotbugs"}:
        raise ValueError("unsupported static scan tool")
    argv = validate_argv(scan_cmd)
    trace_id = trace_id or f"static-{uuid4().hex}"
    result = executor.run(tool_id, "static_scan", argv, cwd=executor.workspace_root, timeout_sec=timeout_sec, trace_id=trace_id)
    payload = {
        "artifact_type": "StaticAnalysisReport",
        "report_id": trace_id,
        "tool_id": tool_id,
        "report_ref": result["diagnostics"].get("stdout_ref"),
        "status": result["status"],
    }
    record = executor.artifacts.write_text(
        f"static/{trace_id}.json",
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
    )
    result["artifact_refs"].append(record.ref)
    result["diagnostics"]["static_report_ref"] = record.ref
    return result
