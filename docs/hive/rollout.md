> **STATUS: PAUSED (2026-10-21).** Hive Wave 1 (commit ledger) was not started. The prerequisite syntax extractor was
> superseded by Phase 2A (`docs/code-intelligence.md`), which now provides the code facts Hive would build on.

# Hive rollout

Process per wave: audit -> short plan -> implement -> adversarial tests -> independent review (fresh, read-only reviewer,
since Codex is unavailable) -> fix validated findings -> rerun -> local commit on branch `hive` -> report.
Nothing is pushed, merged, released or published without explicit approval. The user asked for waves to run in sequence
without pausing; each wave still must pass its own gate before the next starts.

| Wave | Scope | Hard limits |
|---|---|---|
| 1a | TS/JS syntax extractor (WASM tree-sitter), migration v2 | no call resolution |
| 1 | Git DAG ledger, refresh, checkpoints, `changes`, overlay identity | no MCP, no model |
| 2 | Import resolution per snapshot, route detection, feature candidates and confirmed boundaries, provenance traversal | no dynamic-call-graph claims; no model-invented features |
| 3 | Knowledge claims (candidate/approved/retired), evidence records, task/handoff packets, **read-only** stdio MCP | no write MCP tools; no automatic promotion |
| 4 | Advisory impact, JUnit/SARIF import, staleness invalidation | **no test execution**: OS isolation is verified on macOS only, so the runner stays refused |
| 5 | Resource profiles, scale benchmarks on synthetic repos, hardening | multi-user hosted mode is deferred (no demand evidence); no enterprise claims |

## Platform honesty
Everything is developed and tested on macOS (Node 22.23.3) only. Linux, Windows and Node 24 are not run; the report for every wave
states this and lists Windows/Linux-specific code that is unverified.

## Dependency policy
Each new runtime dependency is pinned, licence-checked from its package metadata, installed with `--ignore-scripts`,
and added to the dependency allowlist test with a stated reason.
