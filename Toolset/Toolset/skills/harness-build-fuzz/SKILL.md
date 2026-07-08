# harness-build-fuzz

## Trigger

Use this skill after target triage when the agent needs to build a C/C++ target, register or generate a fuzz harness, run fuzzing, and collect crashes.

## Inputs

- `workspace_root`
- `TargetProfile`
- `ToolPlan`
- seed corpus path or `artifact_ref`
- optional harness source or harness path

## Required MCP Call Sequence

1. Call `toolset.build`.
2. Call `toolset.build_harness` if a harness is needed or already supplied.
3. Call `toolset.start_fuzz` with either `aflpp` or `libfuzzer`, chosen from the probed ToolPlan.
4. Call `toolset.collect_findings` against the fuzz output directory.
5. If a crash candidate exists, call `toolset.reproduce_pov`.

## Output

- `BuildArtifact`
- `HarnessArtifact`
- `FuzzJob`
- `CrashReport`
- `PoV` when reproduction succeeds

## Failure Handling

- If the selected fuzzer is missing, return `status: missing` and try the next probed fuzzer only if the ToolPlan allows it.
- Fuzzing alone is not proof of exploit success; require `toolset.reproduce_pov` before reporting a successful attack.
- Keep all generated seeds, crashes, and logs under the workspace artifact root.
