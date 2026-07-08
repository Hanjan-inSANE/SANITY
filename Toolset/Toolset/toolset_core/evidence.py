from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Iterable, Mapping
from uuid import uuid4

from .artifacts import ArtifactStore


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class EvidenceLedger:
    path: Path

    def __init__(self, path: Path | str) -> None:
        if not path:
            raise ValueError("ledger path is required")
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)

    @property
    def ref(self) -> str:
        return self.path.as_uri()

    def append(self, event: Mapping[str, Any]) -> None:
        if not isinstance(event, Mapping):
            raise TypeError("event must be a mapping")
        payload = dict(event)
        payload.setdefault("recorded_at", utc_now())
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")

    def read_events(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                events.append(json.loads(line))
        return events

    def export_bundle(
        self,
        artifact_store: ArtifactStore,
        trace_id: str,
        verdict: str,
        pov_ref: str | None = None,
        patch_ref: str | None = None,
        baseline_result_ref: str | None = None,
        patched_result_ref: str | None = None,
        test_result_refs: Iterable[str] | None = None,
        trace_refs: Iterable[str] | None = None,
        coverage_refs: Iterable[str] | None = None,
        bundle_id: str | None = None,
    ) -> dict[str, Any]:
        if verdict not in {"defense_verified", "defense_failed", "incomplete", "unknown"}:
            raise ValueError("invalid evidence verdict")
        if not trace_id:
            raise ValueError("trace_id is required")
        bundle_id = bundle_id or f"bundle-{uuid4().hex}"
        events = [event for event in self.read_events() if event.get("trace_id") == trace_id]
        artifact_hashes: dict[str, str] = {}
        for event in events:
            for ref, digest in (event.get("artifact_hashes") or {}).items():
                artifact_hashes[str(ref)] = str(digest)
        bundle = {
            "bundle_id": bundle_id,
            "trace_id": trace_id,
            "created_at": utc_now(),
            "verdict": verdict,
            "pov_ref": pov_ref,
            "patch_ref": patch_ref,
            "baseline_result_ref": baseline_result_ref,
            "patched_result_ref": patched_result_ref,
            "test_result_refs": list(test_result_refs or []),
            "trace_refs": list(trace_refs or []),
            "coverage_refs": list(coverage_refs or []),
            "artifact_hashes": artifact_hashes,
            "ledger_refs": [self.ref],
            "events": events,
        }
        record = artifact_store.write_text(
            f"evidence/{bundle_id}.json",
            json.dumps(bundle, ensure_ascii=False, indent=2, sort_keys=True),
        )
        bundle["bundle_ref"] = record.ref
        bundle["bundle_sha256"] = record.sha256
        return bundle
