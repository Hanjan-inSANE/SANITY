from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import shutil
from typing import Iterable


@dataclass(frozen=True)
class ArtifactRecord:
    ref: str
    path: Path
    sha256: str
    size_bytes: int


class ArtifactStore:
    """Workspace-local artifact store with path containment checks."""

    def __init__(self, root: Path | str) -> None:
        if not root:
            raise ValueError("artifact root is required")
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def resolve(self, relative_path: Path | str) -> Path:
        if not relative_path:
            raise ValueError("relative_path is required")
        candidate = Path(relative_path)
        if candidate.is_absolute():
            resolved = candidate.resolve()
        else:
            resolved = (self.root / candidate).resolve()
        self._ensure_inside(resolved)
        return resolved

    def ref_to_path(self, ref: str) -> Path:
        if not isinstance(ref, str) or not ref.startswith("artifact://"):
            raise ValueError("artifact ref must start with artifact://")
        return self.resolve(ref.removeprefix("artifact://"))

    def write_bytes(self, relative_path: Path | str, data: bytes) -> ArtifactRecord:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes")
        path = self.resolve(relative_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = bytes(data)
        path.write_bytes(payload)
        return self._record(path)

    def write_text(self, relative_path: Path | str, text: str, encoding: str = "utf-8") -> ArtifactRecord:
        if not isinstance(text, str):
            raise TypeError("text must be str")
        return self.write_bytes(relative_path, text.encode(encoding))

    def copy_file(self, source: Path | str, relative_path: Path | str | None = None) -> ArtifactRecord:
        source_path = Path(source).resolve()
        if not source_path.is_file():
            raise FileNotFoundError(str(source_path))
        dest_rel = relative_path or source_path.name
        dest_path = self.resolve(dest_rel)
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        if source_path != dest_path:
            shutil.copy2(source_path, dest_path)
        return self._record(dest_path)

    def hash_file(self, path: Path | str) -> str:
        resolved = Path(path).resolve()
        if resolved.exists():
            # Hashing produced artifacts outside the artifact root is allowed,
            # but storing references is not.
            return "sha256:" + _sha256_file(resolved)
        raise FileNotFoundError(str(resolved))

    def list_refs(self, relative_dir: Path | str = ".") -> list[str]:
        base = self.resolve(relative_dir)
        if not base.exists():
            return []
        files: Iterable[Path] = (p for p in base.rglob("*") if p.is_file())
        return [self._ref(path) for path in files]

    def _record(self, path: Path) -> ArtifactRecord:
        resolved = path.resolve()
        self._ensure_inside(resolved)
        return ArtifactRecord(
            ref=self._ref(resolved),
            path=resolved,
            sha256="sha256:" + _sha256_file(resolved),
            size_bytes=resolved.stat().st_size,
        )

    def _ref(self, path: Path) -> str:
        relative = path.resolve().relative_to(self.root)
        return "artifact://" + relative.as_posix()

    def _ensure_inside(self, path: Path) -> None:
        try:
            path.resolve().relative_to(self.root)
        except ValueError as exc:
            raise ValueError(f"path escapes artifact root: {path}") from exc


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
