from __future__ import annotations

from typing import Any
from uuid import uuid4


def common_response(
    tool_id: str,
    status: str,
    summary: str,
    trace_id: str | None = None,
    artifact_refs: list[str] | None = None,
    diagnostics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if status not in {"success", "failure", "timeout", "missing", "skipped"}:
        raise ValueError("invalid status")
    trace = trace_id or f"trace-{uuid4().hex}"
    return {
        "ok": status == "success",
        "trace_id": trace,
        "tool_id": tool_id,
        "status": status,
        "artifact_refs": artifact_refs or [],
        "summary": summary,
        "diagnostics": diagnostics or {"duration_ms": 0, "exit_code": None},
    }


def exception_response(tool_id: str, exc: Exception, trace_id: str | None = None) -> dict[str, Any]:
    return common_response(
        tool_id=tool_id,
        status="failure",
        summary=f"{tool_id} failed",
        trace_id=trace_id,
        diagnostics={
            "duration_ms": 0,
            "exit_code": None,
            "error_type": type(exc).__name__,
            "error_message": str(exc),
        },
    )
