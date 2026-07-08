from __future__ import annotations

from pathlib import Path
import re
from typing import Mapping, Sequence


ALLOWED_ENV_KEYS = {
    "ASAN_OPTIONS",
    "UBSAN_OPTIONS",
    "MSAN_OPTIONS",
    "TSAN_OPTIONS",
    "LLVM_PROFILE_FILE",
    "GCOV_PREFIX",
    "GCOV_PREFIX_STRIP",
    "AFL_SKIP_CPUFREQ",
    "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES",
    "PATH",
    "SystemRoot",
    "TEMP",
    "TMP",
}

SECRET_KEY_PATTERN = re.compile(r"(token|secret|password|passwd|api[_-]?key|credential)", re.IGNORECASE)
SECRET_VALUE_PATTERN = re.compile(
    r"(?i)(token|secret|password|passwd|api[_-]?key|credential)\s*[:=]\s*([^ \t\r\n]+)"
)


def validate_argv(argv: Sequence[str]) -> list[str]:
    if isinstance(argv, str):
        raise TypeError("argv must be a list of strings; raw shell command strings are forbidden")
    if not isinstance(argv, Sequence) or not argv:
        raise ValueError("argv must be a non-empty sequence")
    out: list[str] = []
    for item in argv:
        if not isinstance(item, str):
            raise TypeError("argv items must be strings")
        if "\x00" in item:
            raise ValueError("argv item contains NUL byte")
        out.append(item)
    return out


def ensure_path_inside(path: Path | str, root: Path | str) -> Path:
    if not path:
        raise ValueError("path is required")
    resolved = Path(path).resolve()
    root_resolved = Path(root).resolve()
    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise ValueError(f"path escapes workspace root: {resolved}") from exc
    return resolved


def filter_env(env: Mapping[str, str] | None) -> dict[str, str]:
    if env is None:
        return {}
    if not isinstance(env, Mapping):
        raise TypeError("env must be a mapping")
    filtered: dict[str, str] = {}
    for key, value in env.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise TypeError("env keys and values must be strings")
        if key in ALLOWED_ENV_KEYS or key.startswith("TOOLSET_"):
            filtered[key] = value
    return filtered


def redact_env(env: Mapping[str, str] | None) -> dict[str, str]:
    safe: dict[str, str] = {}
    for key, value in (env or {}).items():
        safe[key] = "<redacted>" if SECRET_KEY_PATTERN.search(key) else redact_text(value)
    return safe


def redact_text(text: str | bytes | None) -> str:
    if text is None:
        return ""
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    return SECRET_VALUE_PATTERN.sub(lambda m: f"{m.group(1)}=<redacted>", text)


def command_exists(executable: str) -> bool:
    if not executable:
        return False
    candidate = Path(executable)
    if candidate.is_absolute() or any(sep in executable for sep in ("/", "\\")):
        return candidate.exists()
    from shutil import which

    return which(executable) is not None
