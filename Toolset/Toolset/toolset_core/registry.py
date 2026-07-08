from __future__ import annotations

import json
from pathlib import Path
import shutil
from typing import Any, Iterable

from .environment import load_tool_aliases, resolve_argv
from .policy import validate_argv


KIND_ENUM = {
    "builder",
    "test_runner",
    "fuzzer",
    "debugger",
    "tracer",
    "sanitizer",
    "coverage",
    "static_analyzer",
    "patcher",
    "config_hardener",
    "ids_rule_validator",
    "reporter",
    "network_scanner",
    "network_attacker",
}

REQUIRED_DESCRIPTOR_FIELDS = {
    "tool_id",
    "display_name",
    "kind",
    "phase",
    "supported_target",
    "execution",
    "params_schema_ref",
    "output_schema_ref",
    "required_artifacts",
    "produced_artifacts",
    "availability_probe",
    "timeout_sec_default",
    "resource_limits",
    "security_profile",
    "evidence_policy",
}


class ToolRegistry:
    def __init__(self, descriptors: Iterable[dict[str, Any]]) -> None:
        self._descriptors: dict[str, dict[str, Any]] = {}
        for descriptor in descriptors:
            validate_descriptor(descriptor)
            tool_id = descriptor["tool_id"]
            if tool_id in self._descriptors:
                raise ValueError(f"duplicate tool_id: {tool_id}")
            self._descriptors[tool_id] = descriptor

    @classmethod
    def load(cls, path: Path | str | None = None) -> "ToolRegistry":
        registry_path = Path(path) if path else Path(__file__).resolve().parents[1] / "registry" / "tools.yaml"
        data = _load_json_or_yaml_subset(registry_path)
        if not isinstance(data, list):
            raise ValueError("tools registry must be a list")
        return cls(data)

    def get(self, tool_id: str) -> dict[str, Any]:
        if tool_id not in self._descriptors:
            raise KeyError(f"unknown tool_id: {tool_id}")
        return dict(self._descriptors[tool_id])

    def list_tools(
        self,
        kind: str | None = None,
        target: str | None = None,
        phase: str | None = None,
        priority: str | None = None,
    ) -> list[dict[str, Any]]:
        result = []
        for descriptor in self._descriptors.values():
            if kind and descriptor.get("kind") != kind:
                continue
            if target and target not in descriptor.get("supported_target", []):
                continue
            if phase and phase not in descriptor.get("phase", []):
                continue
            if priority and descriptor.get("priority") != priority:
                continue
            result.append(dict(descriptor))
        return result

    def probe(self, tool_id: str, config_path: Path | str | None = None) -> dict[str, Any]:
        descriptor = self.get(tool_id)
        command = descriptor["availability_probe"]["command"]
        if command == ["internal"]:
            return {"tool_id": tool_id, "availability": "available", "command": command}
        validate_argv(command)
        resolved_command = resolve_argv(command, load_tool_aliases(config_path))
        executable = resolved_command[0]
        found = Path(executable).exists() if any(sep in executable for sep in ("/", "\\")) else shutil.which(executable)
        return {
            "tool_id": tool_id,
            "availability": "available" if found else "missing",
            "command": command,
            "resolved_command": resolved_command,
            "resolved": str(found) if found else None,
        }


def validate_descriptor(descriptor: dict[str, Any]) -> None:
    if not isinstance(descriptor, dict):
        raise TypeError("descriptor must be a mapping")
    missing = sorted(REQUIRED_DESCRIPTOR_FIELDS - descriptor.keys())
    if missing:
        raise ValueError(f"descriptor missing required fields: {', '.join(missing)}")
    if descriptor["kind"] not in KIND_ENUM:
        raise ValueError(f"invalid kind: {descriptor['kind']}")
    if not isinstance(descriptor["phase"], list) or not descriptor["phase"]:
        raise ValueError("phase must be a non-empty list")
    if not isinstance(descriptor["supported_target"], list) or not descriptor["supported_target"]:
        raise ValueError("supported_target must be a non-empty list")
    execution = descriptor["execution"]
    if execution.get("mode") not in {"host", "container", "internal"}:
        raise ValueError("execution.mode must be host, container, or internal")
    validate_argv(execution.get("entrypoint", []))
    validate_argv(execution.get("command_template", []))
    probe = descriptor["availability_probe"]
    validate_argv(probe.get("command", []))
    limits = descriptor["resource_limits"]
    for key in ("cpu", "memory_mb", "disk_mb"):
        if key not in limits:
            raise ValueError(f"resource_limits missing {key}")
    security = descriptor["security_profile"]
    if security.get("network") not in {"disabled", "loopback", "sandbox"}:
        raise ValueError("security_profile.network must be disabled, loopback, or sandbox")
    if security.get("write_scope") != "workspace_artifacts_only":
        raise ValueError("write_scope must be workspace_artifacts_only")


def _load_json_or_yaml_subset(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise ValueError(
                f"{path} is not JSON and PyYAML is not installed; use JSON-compatible YAML"
            ) from exc
        return yaml.safe_load(text)
