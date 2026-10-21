# Context-budget governor

Purpose: token savings are the product. Context assembly is a policy, not just a response cap.

## Policy (configurable; defaults)
- `max_response_tokens`: 4,000 per call; `max_session_tokens` optional cap.
- Priority order, filled until budget is exhausted:
  1. exact source locations
  2. relevant symbols + direct dependencies
  3. applicable decisions/constraints (v0.2)
  4. related prior failures (v0.2)
  5. relevant tests + verification status
  6. broader context, only if the task requires it (explicit expand call)
- Structured references (path, range, symbol, one-line signature) instead of file bodies; the agent reads source itself when needed.
- Dedup (optional optimization): items already returned in this process can be collapsed to a reference, but **required context is never omitted solely because an earlier call returned it**; session state is best-effort in-memory and resets on restart.
- Truncation markers and cursor-based pagination; never silent truncation.
- Freshness + provenance on each item; explicit `uncertainty` when results may be incomplete.
- Task-specific expansion via a depth parameter, bounded.

## Fast mode
Small feature requests: symbol-neighborhood only, depth 1, no repo-wide scan.

## Measurement
Benchmarks record total tokens consumed before first meaningful edit, total per task, **and number of retrieval calls**. A design that needs 20 calls to save 2,000 tokens is a failure; the governor aims for few, dense calls. Token counting uses a fixed tokenizer approximation, documented, validated against real agent runs.
