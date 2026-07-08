# pov-reproduce-debug

## Trigger

Use this skill when an agent has a crash candidate or PoV and needs reproducible root-cause evidence.

## Inputs

- `workspace_root`
- `target_cmd`
- `input_blob_ref` or local input path
- baseline build reference

## Required MCP Call Sequence

1. Call `toolset.reproduce_pov` on the baseline build.
2. Call `toolset.debug_gdb` for batch stack trace and registers if GDB is available.
3. Call `toolset.trace_runtime` for syscall trace if strace is available.
4. Call `toolset.run_sanitizer` on an instrumented build when available.
5. Call `toolset.measure_coverage` when coverage artifacts exist.

## Output

- `DebugTrace`
- `RuntimeTrace`
- `SanitizerReport`
- `CoverageReport`
- root cause candidates with evidence refs

## Failure Handling

- If GDB, strace, sanitizer, or coverage tools are missing, keep the missing status in evidence and continue with the remaining tools.
- Do not expose raw exception traces to the agent; use `diagnostics.error_type`, `diagnostics.error_message`, and log artifact refs.
- Do not claim root cause certainty without a reproducing PoV and at least one debug, trace, or sanitizer evidence source.
