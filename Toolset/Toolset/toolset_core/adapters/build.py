from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import uuid4

from ..executor import ToolExecutor
from ..policy import ensure_path_inside


SANITIZER_FLAGS = {
    "asan": "-fsanitize=address -fno-omit-frame-pointer -g",
    "ubsan": "-fsanitize=undefined -fno-omit-frame-pointer -g",
    "asan_ubsan": "-fsanitize=address,undefined -fno-omit-frame-pointer -g",
    "coverage_gcc": "--coverage -g",
    "coverage_llvm": "-fprofile-instr-generate -fcoverage-mapping -g",
}


def build_target(
    executor: ToolExecutor,
    build_system: str,
    source_dir: str | Path,
    build_dir: str | Path | None = None,
    target: str | None = None,
    sanitizer: str | None = None,
    trace_id: str | None = None,
    timeout_sec: int = 1200,
    extra_args: list[str] | None = None,
) -> dict[str, Any]:
    if executor is None:
        raise ValueError("executor is required")
    if not build_system:
        raise ValueError("build_system is required")
    source = executor.workspace_root / source_dir if not Path(source_dir).is_absolute() else Path(source_dir)
    source = executor.workspace_root if str(source_dir) == "." else ensure_path_inside(source.resolve(), executor.workspace_root)
    if build_system == "auto":
        build_system = detect_build_system(source)
    trace_id = trace_id or f"build-{uuid4().hex}"
    build_root = Path(build_dir).resolve() if build_dir and Path(build_dir).is_absolute() else executor.workspace_root / (build_dir or "build")
    build_root = ensure_path_inside(build_root, executor.workspace_root)
    build_root.mkdir(parents=True, exist_ok=True)

    if build_system == "cmake":
        configure = ["cmake", "-S", str(source), "-B", str(build_root)]
        if sanitizer:
            flags = SANITIZER_FLAGS.get(sanitizer)
            if not flags:
                raise ValueError(f"unknown sanitizer profile: {sanitizer}")
            configure.extend(
                [
                    f"-DCMAKE_C_FLAGS={flags}",
                    f"-DCMAKE_CXX_FLAGS={flags}",
                    f"-DCMAKE_EXE_LINKER_FLAGS={flags}",
                ]
            )
        configure.extend(extra_args or [])
        first = executor.run("cmake", "build_configure", configure, cwd=executor.workspace_root, timeout_sec=timeout_sec, trace_id=trace_id)
        if first["status"] != "success":
            return _with_build_artifact(executor, first, build_root, build_system)
        build = ["cmake", "--build", str(build_root)]
        if target:
            build.extend(["--target", target])
        second = executor.run("cmake", "build", build, cwd=executor.workspace_root, timeout_sec=timeout_sec, trace_id=trace_id)
        second["artifact_refs"] = first["artifact_refs"] + second["artifact_refs"]
        second["diagnostics"]["configure_status"] = first["status"]
        return _with_build_artifact(executor, second, build_root, build_system)

    if build_system == "make":
        argv = ["make", "-C", str(build_root if build_dir else source)]
        if target:
            argv.append(target)
        argv.extend(extra_args or [])
        result = executor.run("make", "build", argv, cwd=executor.workspace_root, timeout_sec=timeout_sec, trace_id=trace_id)
        return _with_build_artifact(executor, result, build_root if build_dir else source, build_system)

    if build_system == "ninja":
        argv = ["ninja", "-C", str(build_root if build_dir else source)]
        if target:
            argv.append(target)
        argv.extend(extra_args or [])
        result = executor.run("ninja", "build", argv, cwd=executor.workspace_root, timeout_sec=timeout_sec, trace_id=trace_id)
        return _with_build_artifact(executor, result, build_root if build_dir else source, build_system)

    raise ValueError(f"unsupported build_system: {build_system}")


def detect_build_system(source_dir: Path) -> str:
    if (source_dir / "CMakeLists.txt").exists():
        return "cmake"
    if (source_dir / "build.ninja").exists():
        return "ninja"
    if (source_dir / "Makefile").exists() or (source_dir / "makefile").exists():
        return "make"
    raise ValueError(f"could not detect build system in {source_dir}")


def _with_build_artifact(executor: ToolExecutor, result: dict[str, Any], build_dir: Path, build_system: str) -> dict[str, Any]:
    payload = {
        "artifact_type": "BuildArtifact",
        "build_id": result["trace_id"],
        "build_profile": {"build_system": build_system},
        "build_dir": str(build_dir),
        "exit_code": result["diagnostics"].get("exit_code"),
        "log_refs": result.get("artifact_refs", []),
        "status": result["status"],
    }
    record = executor.artifacts.write_text(f"build/{result['trace_id']}.json", _json(payload))
    result["artifact_refs"].append(record.ref)
    result["diagnostics"]["build_artifact_ref"] = record.ref
    return result


def _json(payload: dict[str, Any]) -> str:
    import json

    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
