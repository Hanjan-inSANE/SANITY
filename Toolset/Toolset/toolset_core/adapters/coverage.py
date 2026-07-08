from __future__ import annotations

from pathlib import Path
import json
from uuid import uuid4

from ..executor import ToolExecutor
from ..policy import ensure_path_inside


def measure_coverage(
    executor: ToolExecutor,
    tool_id: str,
    target: str | Path,
    profile_data: str | Path | None = None,
    trace_id: str | None = None,
    timeout_sec: int = 300,
    extra_args: list[str] | None = None,
) -> dict:
    if executor is None:
        raise ValueError("executor is required")
    if tool_id not in {"gcov", "llvm_cov"}:
        raise ValueError("tool_id must be gcov or llvm_cov")
    trace_id = trace_id or f"coverage-{uuid4().hex}"
    target_path = Path(target).resolve() if Path(target).is_absolute() else executor.workspace_root / target
    target_path = ensure_path_inside(target_path, executor.workspace_root)
    if tool_id == "gcov":
        argv = ["gcov", str(target_path), *(extra_args or [])]
    else:
        if not profile_data:
            raise ValueError("profile_data is required for llvm_cov")
        profile = Path(profile_data).resolve() if Path(profile_data).is_absolute() else executor.workspace_root / profile_data
        profile = ensure_path_inside(profile, executor.workspace_root)
        argv = ["llvm-cov", "show", str(target_path), f"-instr-profile={profile}", *(extra_args or [])]
    result = executor.run(tool_id, "coverage", argv, cwd=executor.workspace_root, timeout_sec=timeout_sec, trace_id=trace_id)
    payload = {
        "artifact_type": "CoverageReport",
        "coverage_id": trace_id,
        "tool_id": tool_id,
        "build_ref": str(target_path),
        "report_ref": result["diagnostics"].get("stdout_ref"),
        "status": result["status"],
    }
    record = executor.artifacts.write_text(
        f"coverage/{trace_id}.json",
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
    )
    result["artifact_refs"].append(record.ref)
    result["diagnostics"]["coverage_report_ref"] = record.ref
    return result
