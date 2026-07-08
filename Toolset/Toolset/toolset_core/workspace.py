from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from .artifacts import ArtifactStore
from .evidence import EvidenceLedger
from .policy import ensure_path_inside


@dataclass
class ToolsetWorkspace:
    workspace_id: str
    root: Path
    artifacts: ArtifactStore
    ledger: EvidenceLedger

    def ensure_inside(self, path: Path | str) -> Path:
        return ensure_path_inside(path, self.root)


def default_runtime_root() -> Path:
    return Path(__file__).resolve().parents[1] / "artifacts" / "workspaces"


def create_workspace(base_dir: Path | str | None = None, workspace_id: str | None = None) -> ToolsetWorkspace:
    workspace_id = workspace_id or f"ws-{uuid4().hex}"
    if not workspace_id.replace("-", "").replace("_", "").isalnum():
        raise ValueError("workspace_id may contain only letters, numbers, hyphen, and underscore")
    base = Path(base_dir).resolve() if base_dir else default_runtime_root().resolve()
    root = (base / workspace_id).resolve()
    root.mkdir(parents=True, exist_ok=True)
    artifacts = ArtifactStore(root / "artifacts")
    ledger = EvidenceLedger(root / "artifacts" / "evidence" / "ledger.jsonl")
    return ToolsetWorkspace(workspace_id=workspace_id, root=root, artifacts=artifacts, ledger=ledger)
