from __future__ import annotations

from pathlib import Path
import json
from typing import Any
from uuid import uuid4

from ..executor import ToolExecutor
from ..policy import ensure_path_inside, validate_argv


def reproduce_pov(
    executor: ToolExecutor,
    target_cmd: list[str],
    input_blob: str | Path | None = None,
    input_blob_ref: str | None = None,
    input_mode: str = "stdin",
    trace_id: str | None = None,
    timeout_sec: int = 120,
) -> dict[str, Any]:
    if executor is None:
        raise ValueError("executor is required")
    argv = validate_argv(target_cmd)
    if input_mode not in {"stdin", "argv"}:
        raise ValueError("input_mode must be stdin or argv")
    trace_id = trace_id or f"pov-{uuid4().hex}"
    input_bytes: bytes | None = None
    input_path: Path | None = None
    if input_blob_ref:
        input_path = executor.artifacts.ref_to_path(input_blob_ref)
    elif input_blob:
        input_path = Path(input_blob).resolve() if Path(input_blob).is_absolute() else executor.workspace_root / input_blob
        input_path = ensure_path_inside(input_path, executor.workspace_root)
    if input_path:
        input_bytes = input_path.read_bytes()
    if input_mode == "argv" and input_path:
        argv = [part if part != "{input}" else str(input_path) for part in argv]

    result = executor.run(
        "pov_replay",
        "pov_replay",
        argv,
        cwd=executor.workspace_root,
        timeout_sec=timeout_sec,
        trace_id=trace_id,
        stdin_bytes=input_bytes if input_mode == "stdin" else None,
    )
    exit_code = result["diagnostics"].get("exit_code")
    reproduced = result["status"] in {"failure", "timeout"} or (isinstance(exit_code, int) and exit_code < 0)
    payload = {
        "artifact_type": "PoV",
        "pov_id": trace_id,
        "input_blob_ref": input_blob_ref or str(input_path or ""),
        "replay_command": argv,
        "exploit_signature": "crash_or_nonzero_exit" if reproduced else "not_reproduced",
        "reproduced": reproduced,
        "exit_code": exit_code,
        "log_refs": result["artifact_refs"],
    }
    record = executor.artifacts.write_text(
        f"pov/{trace_id}.json",
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
    )
    result["artifact_refs"].append(record.ref)
    result["diagnostics"]["pov_ref"] = record.ref
    result["diagnostics"]["reproduced"] = reproduced
    result["summary"] = "PoV reproduced" if reproduced else "PoV did not reproduce"
    return result
