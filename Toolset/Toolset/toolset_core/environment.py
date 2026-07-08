from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping, Sequence

from .policy import validate_argv


def toolset_root() -> Path:
    return Path(__file__).resolve().parents[1]


def default_config_path() -> Path:
    return toolset_root() / "config" / "toolset.local.json"


def load_environment_config(config_path: str | Path | None = None) -> dict[str, Any]:
    selected = Path(config_path).expanduser() if config_path else None
    if selected is None:
        env_path = os.environ.get("TOOLSET_CONFIG")
        selected = Path(env_path).expanduser() if env_path else default_config_path()
    if not selected.exists():
        return {"tool_aliases": {}, "env": {}}
    payload = json.loads(selected.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Toolset environment config must be a JSON object")
    payload.setdefault("tool_aliases", {})
    payload.setdefault("env", {})
    if not isinstance(payload["tool_aliases"], dict):
        raise ValueError("tool_aliases must be an object")
    if not isinstance(payload["env"], dict):
        raise ValueError("env must be an object")
    return payload


def load_tool_aliases(config_path: str | Path | None = None) -> dict[str, str | list[str]]:
    config = load_environment_config(config_path)
    aliases: dict[str, str | list[str]] = {}
    for key, value in config.get("tool_aliases", {}).items():
        if not isinstance(key, str):
            raise ValueError("tool alias keys must be strings")
        if isinstance(value, str):
            aliases[key] = value
        elif isinstance(value, list) and all(isinstance(item, str) for item in value):
            aliases[key] = list(value)
        else:
            raise ValueError(f"invalid alias value for {key}")
    return aliases


def resolve_argv(argv: Sequence[str], aliases: Mapping[str, str | list[str]] | None = None) -> list[str]:
    argv_list = validate_argv(argv)
    aliases = aliases or {}
    if not argv_list:
        return argv_list
    replacement = aliases.get(argv_list[0])
    if replacement is None:
        return argv_list
    if isinstance(replacement, str):
        return [replacement, *argv_list[1:]]
    return [*replacement, *argv_list[1:]]
