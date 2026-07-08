from __future__ import annotations

import argparse
import json
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


TOOLSET_ROOT = Path(__file__).resolve().parents[1]
if str(TOOLSET_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOLSET_ROOT))

from toolset_core.environment import default_config_path, load_tool_aliases, resolve_argv
from toolset_core.registry import ToolRegistry


def main() -> int:
    parser = argparse.ArgumentParser(description="Check host availability for DAH Toolset registry tools.")
    parser.add_argument("--registry", default=str(TOOLSET_ROOT / "registry" / "tools.yaml"))
    parser.add_argument("--config", default=None, help="Toolset local config JSON. Defaults to TOOLSET_CONFIG or Toolset/config/toolset.local.json.")
    parser.add_argument("--priority", default="P0")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    parser.add_argument("--write-config", action="store_true", help="Write a starter Toolset/config/toolset.local.json alias file if absent.")
    parser.add_argument("--fail-on-missing", action="store_true", help="Exit non-zero when any checked external tool is missing.")
    args = parser.parse_args()

    if args.write_config:
        write_config_if_absent(args.config)

    registry = ToolRegistry.load(args.registry)
    aliases = load_tool_aliases(args.config)
    rows = []
    for descriptor in registry.list_tools(priority=args.priority):
        probe_cmd = descriptor["availability_probe"]["command"]
        if probe_cmd == ["internal"]:
            rows.append(
                {
                    "tool_id": descriptor["tool_id"],
                    "kind": descriptor["kind"],
                    "status": "available",
                    "command": probe_cmd,
                    "resolved_command": probe_cmd,
                    "version": "internal",
                }
            )
            continue
        resolved = resolve_argv(probe_cmd, aliases)
        executable = resolved[0]
        resolved_path = Path(executable) if any(sep in executable for sep in ("/", "\\")) else shutil.which(executable)
        status = "available" if resolved_path and Path(resolved_path).exists() else "missing"
        version = ""
        if status == "available":
            returncode, version = run_probe(resolved)
            if returncode != 0:
                status = "probe_failed"
        rows.append(
            {
                "tool_id": descriptor["tool_id"],
                "kind": descriptor["kind"],
                "status": status,
                "command": probe_cmd,
                "resolved_command": resolved,
                "resolved_path": str(resolved_path) if resolved_path else None,
                "version": version,
            }
        )

    payload = {
        "toolset_root": str(TOOLSET_ROOT),
        "config_path": str(Path(args.config).resolve()) if args.config else str(default_config_path()),
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": sys.version.split()[0],
        },
        "tools": rows,
        "summary": {
            "checked": len(rows),
            "available": sum(1 for row in rows if row["status"] == "available"),
            "missing": sum(1 for row in rows if row["status"] == "missing"),
            "probe_failed": sum(1 for row in rows if row["status"] == "probe_failed"),
        },
    }
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print_human(payload)
    if args.fail_on_missing and (payload["summary"]["missing"] or payload["summary"]["probe_failed"]):
        return 2
    return 0


def run_probe(argv: list[str]) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=15,
            text=True,
            shell=False,
        )
    except Exception as exc:  # noqa: BLE001
        return 1, f"probe failed: {type(exc).__name__}: {exc}"
    return completed.returncode, "\n".join(completed.stdout.splitlines()[:3])


def write_config_if_absent(config_arg: str | None) -> None:
    target = Path(config_arg).resolve() if config_arg else default_config_path()
    if target.exists():
        print(f"Config already exists: {target}")
        return
    source = TOOLSET_ROOT / "config" / "toolset.local.example.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    print(f"Wrote starter config: {target}")


def print_human(payload: dict[str, Any]) -> None:
    print(f"Toolset root: {payload['toolset_root']}")
    print(f"Config path: {payload['config_path']}")
    print(
        "Platform: "
        f"{payload['platform']['system']} {payload['platform']['release']} "
        f"{payload['platform']['machine']} / Python {payload['platform']['python']}"
    )
    print("")
    print(f"{'tool_id':<18} {'kind':<14} {'status':<13} resolved")
    print("-" * 90)
    for row in payload["tools"]:
        resolved = " ".join(row["resolved_command"])
        print(f"{row['tool_id']:<18} {row['kind']:<14} {row['status']:<13} {resolved}")
    print("-" * 90)
    summary = payload["summary"]
    print(
        "checked="
        f"{summary['checked']} available={summary['available']} "
        f"missing={summary['missing']} probe_failed={summary['probe_failed']}"
    )


if __name__ == "__main__":
    raise SystemExit(main())
