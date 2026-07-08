from __future__ import annotations

import json
from uuid import uuid4

from ..evidence import utc_now
from ..executor import ToolExecutor


def compare_baseline(
    executor: ToolExecutor,
    baseline_pov_reproduces: bool,
    patched_pov_blocked: bool,
    patched_build_success: bool,
    regression_tests_pass: bool,
    no_new_sanitizer_finding_on_replay: bool,
    evidence_bundle_complete: bool,
    trace_id: str | None = None,
) -> dict:
    if executor is None:
        raise ValueError("executor is required")
    trace_id = trace_id or f"compare-{uuid4().hex}"
    gates = {
        "patched_build_success": bool(patched_build_success),
        "regression_tests_pass": bool(regression_tests_pass),
        "baseline_pov_reproduces": bool(baseline_pov_reproduces),
        "patched_pov_blocked": bool(patched_pov_blocked),
        "no_new_sanitizer_finding_on_replay": bool(no_new_sanitizer_finding_on_replay),
        "evidence_bundle_complete": bool(evidence_bundle_complete),
    }
    verdict = "defense_verified" if all(gates.values()) else "defense_failed"
    payload = {
        "artifact_type": "DefenseComparison",
        "comparison_id": trace_id,
        "gates": gates,
        "verdict": verdict,
    }
    record = executor.artifacts.write_text(
        f"compare/{trace_id}.json",
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
    )
    result = {
        "ok": verdict == "defense_verified",
        "trace_id": trace_id,
        "tool_id": "compare_baseline",
        "status": "success" if verdict == "defense_verified" else "failure",
        "artifact_refs": [record.ref],
        "summary": verdict,
        "diagnostics": {
            "exit_code": 0,
            "duration_ms": 0,
            "comparison_ref": record.ref,
            "verdict": verdict,
            "gates": gates,
        },
    }
    executor.ledger.append(
        {
            "trace_id": trace_id,
            "event_type": "tool_invocation",
            "tool_id": "compare_baseline",
            "phase": "defense_verification",
            "workspace_id": executor.workspace_root.name,
            "command": [],
            "cwd": str(executor.workspace_root),
            "env_redacted": {},
            "started_at": utc_now(),
            "ended_at": utc_now(),
            "duration_ms": 0,
            "exit_code": 0,
            "status": result["status"],
            "produced_artifacts": [record.ref],
            "artifact_hashes": {record.ref: record.sha256},
            "summary": verdict,
        }
    )
    return result
