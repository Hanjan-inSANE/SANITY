from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path
import subprocess
import time
from typing import Any, Mapping, Sequence
from uuid import uuid4

from .artifacts import ArtifactStore
from .evidence import EvidenceLedger
from .environment import load_tool_aliases, resolve_argv
from .policy import command_exists, ensure_path_inside, filter_env, redact_env, redact_text, validate_argv


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ExecutionResult:
    ok: bool
    trace_id: str
    tool_id: str
    status: str
    artifact_refs: list[str]
    summary: str
    diagnostics: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "trace_id": self.trace_id,
            "tool_id": self.tool_id,
            "status": self.status,
            "artifact_refs": self.artifact_refs,
            "summary": self.summary,
            "diagnostics": self.diagnostics,
        }


class ToolExecutor:
    """Run argv-only tool invocations and append structured evidence."""

    def __init__(
        self,
        workspace_root: Path | str,
        artifact_store: ArtifactStore | None = None,
        ledger: EvidenceLedger | None = None,
        config_path: Path | str | None = None,
    ) -> None:
        if not workspace_root:
            raise ValueError("workspace_root is required")
        self.workspace_root = Path(workspace_root).resolve()
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        self.artifacts = artifact_store or ArtifactStore(self.workspace_root / "artifacts")
        self.ledger = ledger or EvidenceLedger(self.workspace_root / "artifacts" / "evidence" / "ledger.jsonl")
        self.tool_aliases = load_tool_aliases(config_path)

    def run(
        self,
        tool_id: str,
        phase: str,
        argv: Sequence[str],
        cwd: Path | str | None = None,
        env: Mapping[str, str] | None = None,
        timeout_sec: int = 60,
        trace_id: str | None = None,
        stdin_bytes: bytes | None = None,
        extra_artifact_paths: Sequence[Path | str] | None = None,
    ) -> dict[str, Any]:
        if not tool_id:
            raise ValueError("tool_id is required")
        if not phase:
            raise ValueError("phase is required")
        if timeout_sec <= 0:
            raise ValueError("timeout_sec must be positive")
        argv_list = validate_argv(argv)
        resolved_argv = resolve_argv(argv_list, self.tool_aliases)
        trace_id = trace_id or f"trace-{uuid4().hex}"
        run_cwd = ensure_path_inside(cwd or self.workspace_root, self.workspace_root)
        safe_env = filter_env(env)
        merged_env = os.environ.copy()
        merged_env.update(safe_env)

        started_at = _utc_now()
        start = time.monotonic()
        stdout_bytes = b""
        stderr_bytes = b""
        exit_code: int | None = None
        status = "success"
        error_type: str | None = None
        error_message: str | None = None

        if not command_exists(resolved_argv[0]):
            status = "missing"
            duration_ms = 0
            stdout_record = self.artifacts.write_text(f"logs/{trace_id}/{tool_id}.stdout.txt", "")
            stderr_record = self.artifacts.write_text(
                f"logs/{trace_id}/{tool_id}.stderr.txt",
                f"missing executable: {resolved_argv[0]}\n",
            )
            result = self._result(
                trace_id,
                tool_id,
                status,
                [stdout_record.ref, stderr_record.ref],
                f"{tool_id} executable is missing",
                {
                    "exit_code": None,
                    "duration_ms": duration_ms,
                    "stdout_ref": stdout_record.ref,
                    "stderr_ref": stderr_record.ref,
                    "error_type": "MissingExecutable",
                    "error_message": f"missing executable: {resolved_argv[0]}",
                    "original_command": argv_list,
                    "resolved_command": resolved_argv,
                },
            )
            self._append_event(
                trace_id,
                tool_id,
                phase,
                resolved_argv,
                run_cwd,
                safe_env,
                started_at,
                _utc_now(),
                duration_ms,
                None,
                result,
                {stdout_record.ref: stdout_record.sha256, stderr_record.ref: stderr_record.sha256},
            )
            return result.as_dict()

        try:
            completed = subprocess.run(
                resolved_argv,
                cwd=str(run_cwd),
                env=merged_env,
                input=stdin_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout_sec,
                shell=False,
                check=False,
            )
            stdout_bytes = completed.stdout
            stderr_bytes = completed.stderr
            exit_code = completed.returncode
            status = "success" if exit_code == 0 else "failure"
        except subprocess.TimeoutExpired as exc:
            status = "timeout"
            stdout_bytes = exc.stdout or b""
            stderr_bytes = exc.stderr or b""
            error_type = "TimeoutExpired"
            error_message = f"timeout after {timeout_sec}s"
        except Exception as exc:  # noqa: BLE001 - structured failure surface for agent tools.
            status = "failure"
            error_type = type(exc).__name__
            error_message = str(exc)
            stderr_bytes = error_message.encode("utf-8", errors="replace")

        ended_at = _utc_now()
        duration_ms = int((time.monotonic() - start) * 1000)
        stdout_text = redact_text(stdout_bytes)
        stderr_text = redact_text(stderr_bytes)
        stdout_record = self.artifacts.write_text(f"logs/{trace_id}/{tool_id}.stdout.txt", stdout_text)
        stderr_record = self.artifacts.write_text(f"logs/{trace_id}/{tool_id}.stderr.txt", stderr_text)
        artifact_refs = [stdout_record.ref, stderr_record.ref]
        artifact_hashes = {stdout_record.ref: stdout_record.sha256, stderr_record.ref: stderr_record.sha256}

        for produced in extra_artifact_paths or []:
            produced_path = Path(produced)
            if produced_path.exists() and produced_path.is_file():
                digest = self.artifacts.hash_file(produced_path)
                ref = produced_path.as_uri()
                artifact_refs.append(ref)
                artifact_hashes[ref] = digest

        diagnostics: dict[str, Any] = {
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "stdout_ref": stdout_record.ref,
            "stderr_ref": stderr_record.ref,
        }
        if error_type:
            diagnostics["error_type"] = error_type
            diagnostics["error_message"] = error_message or ""

        result = self._result(
            trace_id,
            tool_id,
            status,
            artifact_refs,
                f"{tool_id} {status}",
                diagnostics,
        )
        result.diagnostics["original_command"] = argv_list
        result.diagnostics["resolved_command"] = resolved_argv
        self._append_event(
            trace_id,
            tool_id,
            phase,
            resolved_argv,
            run_cwd,
            safe_env,
            started_at,
            ended_at,
            duration_ms,
            exit_code,
            result,
            artifact_hashes,
        )
        return result.as_dict()

    def skipped(self, tool_id: str, trace_id: str, summary: str, diagnostics: dict[str, Any] | None = None) -> dict[str, Any]:
        result = self._result(trace_id, tool_id, "skipped", [], summary, diagnostics or {"duration_ms": 0})
        self.ledger.append(
            {
                "trace_id": trace_id,
                "event_type": "tool_invocation",
                "tool_id": tool_id,
                "phase": "skipped",
                "workspace_id": self.workspace_root.name,
                "command": [],
                "cwd": str(self.workspace_root),
                "env_redacted": {},
                "started_at": _utc_now(),
                "ended_at": _utc_now(),
                "duration_ms": 0,
                "exit_code": None,
                "status": "skipped",
                "produced_artifacts": [],
                "artifact_hashes": {},
                "summary": summary,
            }
        )
        return result.as_dict()

    def _result(
        self,
        trace_id: str,
        tool_id: str,
        status: str,
        artifact_refs: list[str],
        summary: str,
        diagnostics: dict[str, Any],
    ) -> ExecutionResult:
        return ExecutionResult(
            ok=status == "success",
            trace_id=trace_id,
            tool_id=tool_id,
            status=status,
            artifact_refs=artifact_refs,
            summary=summary,
            diagnostics=diagnostics,
        )

    def _append_event(
        self,
        trace_id: str,
        tool_id: str,
        phase: str,
        argv: list[str],
        cwd: Path,
        env: Mapping[str, str],
        started_at: str,
        ended_at: str,
        duration_ms: int,
        exit_code: int | None,
        result: ExecutionResult,
        artifact_hashes: Mapping[str, str],
    ) -> None:
        self.ledger.append(
            {
                "trace_id": trace_id,
                "event_type": "tool_invocation",
                "tool_id": tool_id,
                "phase": phase,
                "workspace_id": self.workspace_root.name,
                "command": argv,
                "cwd": str(cwd),
                "env_redacted": redact_env(env),
                "started_at": started_at,
                "ended_at": ended_at,
                "duration_ms": duration_ms,
                "exit_code": exit_code,
                "status": result.status,
                "stdout_ref": result.diagnostics.get("stdout_ref"),
                "stderr_ref": result.diagnostics.get("stderr_ref"),
                "produced_artifacts": result.artifact_refs,
                "artifact_hashes": dict(artifact_hashes),
                "summary": result.summary,
                "diagnostics": result.diagnostics,
            }
        )
