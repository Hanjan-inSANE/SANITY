# defense-patch-verify

## Trigger

Use this skill when a confirmed PoV and candidate patch are available and the agent must verify that the defense works without breaking normal behavior.

## Inputs

- `workspace_root`
- candidate unified diff or patch artifact
- baseline PoV replay command and input
- patched build and regression test parameters

## Required MCP Call Sequence

1. Create or receive a unified diff.
2. Call `toolset.apply_patch`.
3. Call `toolset.build` on the patched workspace.
4. Call `toolset.run_tests`.
5. Call `toolset.reproduce_pov` on the patched build.
6. Call `toolset.run_sanitizer`.
7. Call `toolset.trace_runtime`.
8. Call `toolset.measure_coverage`.
9. Call `toolset.compare_baseline`.

## Defense Success Predicate

```text
patched_build_success
AND regression_tests_pass
AND baseline_pov_reproduces
AND patched_pov_blocked
AND no_new_sanitizer_finding_on_replay
AND evidence_bundle_complete
```

## Output

- `PatchArtifact`
- patched `BuildArtifact`
- `TestResult`
- patched `PoV` replay result
- `DefenseComparison`

## Failure Handling

- If only `patched_pov_blocked` passes but regression tests fail, mark the defense as failed.
- If patch application is not clean, regenerate the diff; do not partially apply raw shell edits.
- The original attacker workspace must remain unpatched when downstream reachability matters.
