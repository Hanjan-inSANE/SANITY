from __future__ import annotations

from pathlib import Path
import json
import shutil
from typing import Any
from uuid import uuid4

from ..evidence import utc_now
from ..executor import ToolExecutor
from ..policy import ensure_path_inside, validate_argv


def start_fuzz(
    executor: ToolExecutor,
    tool_id: str,
    target_cmd: list[str],
    seeds_dir: str | Path,
    output_dir: str | Path | None = None,
    trace_id: str | None = None,
    timeout_sec: int = 3600,
    max_total_time: int | None = None,
    runs: int | None = None,
    extra_args: list[str] | None = None,
) -> dict[str, Any]:
    if executor is None:
        raise ValueError("executor is required")
    validate_argv(target_cmd)
    if not tool_id:
        raise ValueError("tool_id is required")
    trace_id = trace_id or f"fuzz-{uuid4().hex}"
    seeds = Path(seeds_dir).resolve() if Path(seeds_dir).is_absolute() else executor.workspace_root / seeds_dir
    seeds = ensure_path_inside(seeds, executor.workspace_root)
    seeds.mkdir(parents=True, exist_ok=True)
    output = Path(output_dir).resolve() if output_dir and Path(output_dir).is_absolute() else executor.workspace_root / (output_dir or f"artifacts/fuzz/{trace_id}")
    output = ensure_path_inside(output, executor.workspace_root)
    output.mkdir(parents=True, exist_ok=True)

    if tool_id in ("aflpp", "aflnet"):
        argv = ["afl-fuzz", "-i", str(seeds), "-o", str(output), *(extra_args or []), "--", *target_cmd]
        result = executor.run(tool_id, "attack_discovery", argv, cwd=executor.workspace_root, timeout_sec=timeout_sec, trace_id=trace_id)
        return _with_fuzz_artifact(executor, result, tool_id, output)

    if tool_id == "libfuzzer":
        artifact_prefix = output / "artifacts"
        artifact_prefix.mkdir(parents=True, exist_ok=True)
        argv = [*target_cmd, str(seeds)]
        if max_total_time is not None:
            argv.append(f"-max_total_time={max_total_time}")
        if runs is not None:
            argv.append(f"-runs={runs}")
        argv.append(f"-artifact_prefix={artifact_prefix}{Path('/')}")
        argv.extend(extra_args or [])
        result = executor.run("libfuzzer", "attack_discovery", argv, cwd=executor.workspace_root, timeout_sec=timeout_sec, trace_id=trace_id)
        return _with_fuzz_artifact(executor, result, tool_id, output)

    if tool_id == "honggfuzz":
        argv = ["honggfuzz", "-i", str(seeds), "-W", str(output), *(extra_args or []), "--", *target_cmd]
        result = executor.run("honggfuzz", "attack_discovery", argv, cwd=executor.workspace_root, timeout_sec=timeout_sec, trace_id=trace_id)
        return _with_fuzz_artifact(executor, result, tool_id, output)

    raise ValueError(f"unsupported fuzzer: {tool_id}")


def collect_findings(
    executor: ToolExecutor,
    fuzz_output_dir: str | Path,
    trace_id: str | None = None,
) -> dict[str, Any]:
    if executor is None:
        raise ValueError("executor is required")
    trace_id = trace_id or f"findings-{uuid4().hex}"
    output = Path(fuzz_output_dir).resolve() if Path(fuzz_output_dir).is_absolute() else executor.workspace_root / fuzz_output_dir
    output = ensure_path_inside(output, executor.workspace_root)
    if not output.exists():
        return executor.skipped("collect_findings", trace_id, f"fuzz output directory does not exist: {output}")

    crash_candidates: list[Path] = []
    for pattern in ("**/crashes/id:*", "**/crash-*", "**/timeout-*", "**/artifacts/crash-*"):
        crash_candidates.extend(path for path in output.glob(pattern) if path.is_file())
    copied_refs: list[str] = []
    for crash in crash_candidates:
        rel = f"findings/{trace_id}/{crash.name}"
        copied_refs.append(executor.artifacts.copy_file(crash, rel).ref)
    payload = {
        "artifact_type": "CrashReport",
        "crash_id": trace_id,
        "job_id": trace_id,
        "crash_count": len(crash_candidates),
        "input_blob_refs": copied_refs,
        "dedup_signature": _dedup_signature(crash_candidates),
    }
    record = executor.artifacts.write_text(
        f"findings/{trace_id}/crash_report.json",
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
    )
    status = "success" if crash_candidates else "skipped"
    result = {
        "ok": bool(crash_candidates),
        "trace_id": trace_id,
        "tool_id": "collect_findings",
        "status": status,
        "artifact_refs": [*copied_refs, record.ref],
        "summary": f"collected {len(crash_candidates)} crash candidates",
        "diagnostics": {
            "exit_code": 0,
            "duration_ms": 0,
            "crash_count": len(crash_candidates),
            "crash_report_ref": record.ref,
        },
    }
    executor.ledger.append(
        {
            "trace_id": trace_id,
            "event_type": "tool_invocation",
            "tool_id": "collect_findings",
            "phase": "attack_discovery",
            "workspace_id": executor.workspace_root.name,
            "command": [],
            "cwd": str(output),
            "env_redacted": {},
            "started_at": utc_now(),
            "ended_at": utc_now(),
            "duration_ms": 0,
            "exit_code": 0,
            "status": status,
            "produced_artifacts": result["artifact_refs"],
            "artifact_hashes": {record.ref: record.sha256},
            "summary": result["summary"],
        }
    )
    return result


def _with_fuzz_artifact(executor: ToolExecutor, result: dict[str, Any], tool_id: str, output_dir: Path) -> dict[str, Any]:
    payload = {
        "artifact_type": "FuzzJob",
        "job_id": result["trace_id"],
        "tool_id": tool_id,
        "output_dir": str(output_dir),
        "status": result["status"],
        "log_refs": result["artifact_refs"],
    }
    record = executor.artifacts.write_text(
        f"fuzz/{result['trace_id']}/fuzz_job.json",
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
    )
    result["artifact_refs"].append(record.ref)
    result["diagnostics"]["fuzz_job_ref"] = record.ref
    return result


def _dedup_signature(paths: list[Path]) -> str:
    if not paths:
        return ""
    import hashlib

    digest = hashlib.sha256()
    for path in sorted(paths):
        digest.update(path.name.encode("utf-8", errors="replace"))
        digest.update(str(path.stat().st_size).encode("ascii"))
        with path.open("rb") as fh:
            digest.update(fh.read(4096))
    return "sha256:" + digest.hexdigest()
