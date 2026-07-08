"""Core building blocks for DAH Toolset.

The package intentionally exposes adapters and structured tool-call helpers,
not a monolithic harness program. Agents should call the MCP-facing functions
or these adapters as needed for target triage, build, fuzzing, replay,
debugging, patch verification, and evidence export.
"""

from .artifacts import ArtifactRecord, ArtifactStore
from .evidence import EvidenceLedger
from .executor import ToolExecutor
from .registry import ToolRegistry
from .workspace import ToolsetWorkspace, create_workspace

__all__ = [
    "ArtifactRecord",
    "ArtifactStore",
    "EvidenceLedger",
    "ToolExecutor",
    "ToolRegistry",
    "ToolsetWorkspace",
    "create_workspace",
]
