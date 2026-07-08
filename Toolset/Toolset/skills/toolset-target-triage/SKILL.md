# toolset-target-triage

## Trigger

Use this skill when an agent receives a new DAH challenge workspace and must identify the target language, build system, runtime, candidate attack surface, and available Toolset tools.

## Inputs

- `challenge_root`: local challenge workspace path
- `workspace_id` optional
- `target_hint` optional language or platform hint

## Required MCP Call Sequence

1. Call `toolset.create_workspace` to create or register the Toolset workspace and artifact root.
2. Call `toolset.detect_target` on the challenge workspace or Toolset workspace clone.
3. Call `attack_rag_query` only through the external RAG contract when CWE, CVE, CAPEC, ATT&CK, or similar historical evidence is needed. Do not import or modify `attack-rag/`.
4. Call `toolset.list_tools` with the detected target language and P0 priority.
5. Call `toolset.probe_tool` for candidate tools and keep missing tools in the ToolPlan with `availability: missing`.

## Output

- `TargetProfile`
- `ToolPlan` with available, missing, and skipped tools
- Evidence refs for target detection and probes

## Failure Handling

- If detection is ambiguous, report `language: unknown` or `build_system: unknown`; do not invent target facts.
- If every candidate tool is missing, stop before raw shell execution and return a structured blocker.
- Never ask the agent to run arbitrary shell commands outside Toolset MCP tools.
