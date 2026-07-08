from __future__ import annotations

from pathlib import Path
import json
from uuid import uuid4

from ..executor import ToolExecutor
from ..policy import ensure_path_inside


def apply_unified_diff(
    executor: ToolExecutor,
    patch_text: str | None = None,
    patch_path: str | Path | None = None,
    trace_id: str | None = None,
    timeout_sec: int = 120,
) -> dict:
    if executor is None:
        raise ValueError("executor is required")
    if not patch_text and not patch_path:
        raise ValueError("patch_text or patch_path is required")
    trace_id = trace_id or f"patch-{uuid4().hex}"
    if patch_text is not None:
        patch_record = executor.artifacts.write_text(f"patch/{trace_id}.diff", patch_text)
        patch_file = patch_record.path
    else:
        source = Path(patch_path).resolve() if Path(patch_path).is_absolute() else executor.workspace_root / patch_path
        source = ensure_path_inside(source, executor.workspace_root)
        patch_record = executor.artifacts.copy_file(source, f"patch/{trace_id}.diff")
        patch_file = patch_record.path
    check = executor.run(
        "git_apply",
        "patch_check",
        ["git", "apply", "--check", str(patch_file)],
        cwd=executor.workspace_root,
        timeout_sec=timeout_sec,
        trace_id=trace_id,
    )
    if check["status"] != "success":
        check["artifact_refs"].append(patch_record.ref)
        check["diagnostics"]["patch_ref"] = patch_record.ref
        check["summary"] = "patch did not cleanly apply"
        return _with_patch_artifact(executor, check, patch_record.ref, applied=False)

    result = executor.run(
        "git_apply",
        "patch_apply",
        ["git", "apply", str(patch_file)],
        cwd=executor.workspace_root,
        timeout_sec=timeout_sec,
        trace_id=trace_id,
    )
    result["artifact_refs"] = [patch_record.ref, *check["artifact_refs"], *result["artifact_refs"]]
    result["diagnostics"]["patch_ref"] = patch_record.ref
    return _with_patch_artifact(executor, result, patch_record.ref, applied=result["status"] == "success")


def _with_patch_artifact(executor: ToolExecutor, result: dict, patch_ref: str, applied: bool) -> dict:
    payload = {
        "artifact_type": "PatchArtifact",
        "patch_id": result["trace_id"],
        "diff_ref": patch_ref,
        "touched_files": [],
        "apply_result_ref": result["diagnostics"].get("stdout_ref"),
        "applied": applied,
        "status": result["status"],
    }
    record = executor.artifacts.write_text(
        f"patch/{result['trace_id']}.json",
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
    )
    result["artifact_refs"].append(record.ref)
    result["diagnostics"]["patch_artifact_ref"] = record.ref
    return result
