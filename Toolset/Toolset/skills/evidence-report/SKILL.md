# evidence-report

## Trigger

Use this skill when attack and defense verification evidence must be exported into a final bundle and report.

## Inputs

- `workspace_root`
- verification `trace_id`
- PoV, patch, baseline, patched, test, trace, and coverage refs
- final verdict

## Required MCP Call Sequence

1. Call `toolset.export_evidence`.
2. Call `toolset.generate_report`.
3. Verify that report artifact hashes match the evidence bundle artifact hashes.

## Output

- `DefenseEvidenceBundle`
- final report markdown or PDF artifact
- patch diff ref
- PoV reproduction artifact refs

## Failure Handling

- If any required hash is missing, return `verdict: incomplete`.
- Do not generate a report that omits command, exit code, timestamp, log refs, or artifact hashes for critical gates.
- Do not cite external RAG content as evidence unless the RAG result has its own artifact ref and provenance.
