from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from ..evidence import utc_now
from ..executor import ToolExecutor


def generate_report(
    executor: ToolExecutor,
    bundle_ref: str,
    trace_id: str | None = None,
    title: str = "DAH Toolset Defense Evidence Report",
) -> dict:
    if executor is None:
        raise ValueError("executor is required")
    if not bundle_ref:
        raise ValueError("bundle_ref is required")
    trace_id = trace_id or f"report-{uuid4().hex}"
    bundle_path = executor.artifacts.ref_to_path(bundle_ref) if bundle_ref.startswith("artifact://") else Path(bundle_ref)
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    artifact_hash_lines = "\n".join(f"- `{ref}`: `{digest}`" for ref, digest in sorted(bundle.get("artifact_hashes", {}).items()))
    gate_lines = ""
    for event in bundle.get("events", []):
        diagnostics = event.get("diagnostics") or {}
        gates = diagnostics.get("gates")
        if gates:
            gate_lines = "\n".join(f"- {name}: {'PASS' if passed else 'FAIL'}" for name, passed in gates.items())
    report = f"""# {title}

## Summary

- Bundle ID: `{bundle.get('bundle_id')}`
- Trace ID: `{bundle.get('trace_id')}`
- Verdict: `{bundle.get('verdict')}`
- Created At: `{bundle.get('created_at')}`

## Defense Verification Gates

{gate_lines or '- Gate details are not present in this bundle.'}

## Key Artifacts

- PoV: `{bundle.get('pov_ref')}`
- Patch: `{bundle.get('patch_ref')}`
- Baseline Result: `{bundle.get('baseline_result_ref')}`
- Patched Result: `{bundle.get('patched_result_ref')}`
- Tests: `{', '.join(bundle.get('test_result_refs') or [])}`
- Runtime/Debug Traces: `{', '.join(bundle.get('trace_refs') or [])}`
- Coverage: `{', '.join(bundle.get('coverage_refs') or [])}`

## Artifact Hashes

{artifact_hash_lines or '- No artifact hashes recorded.'}
"""
    record = executor.artifacts.write_text(f"reports/{trace_id}.md", report)
    result = {
        "ok": True,
        "trace_id": trace_id,
        "tool_id": "toolset_reporter",
        "status": "success",
        "artifact_refs": [record.ref],
        "summary": "report generated",
        "diagnostics": {"exit_code": 0, "duration_ms": 0, "report_ref": record.ref},
    }
    executor.ledger.append(
        {
            "trace_id": trace_id,
            "event_type": "tool_invocation",
            "tool_id": "toolset_reporter",
            "phase": "report",
            "workspace_id": executor.workspace_root.name,
            "command": ["toolset.generate_report", bundle_ref],
            "cwd": str(executor.workspace_root),
            "env_redacted": {},
            "started_at": utc_now(),
            "ended_at": utc_now(),
            "duration_ms": 0,
            "exit_code": 0,
            "status": "success",
            "produced_artifacts": [record.ref],
            "artifact_hashes": {record.ref: record.sha256},
            "summary": "report generated",
        }
    )
    return result
