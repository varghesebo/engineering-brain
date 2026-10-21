# Verification model

## v0.1 scope (deliberately small)
`engbrain verify` (no flag) = discovery and evidence inspection only; works on every OS offline. `engbrain verify --run <suite>` = execution; refused with an explanation if the required isolation is unavailable (e.g. Windows strict mode in v0.1).
1. Discovers available test commands (package scripts, jest/vitest/pytest configs).
2. With `--run` and explicit authorization, runs a named known suite in the sandbox for the active security mode.
3. Stores evidence bound to exact source fingerprint (revision + dirty fingerprint) and environment fingerprint (OS, runtime versions, command).
4. Reports **evidence gaps** (code with no known test, evidence stale after changes).
It does not claim to select tests via the graph or to prove unknown behavior correct. Graph-based regression selection is v0.3 and is not advertised before the graph-to-test mapping exists.

## Evidence states
Stored outcomes (separate): `passed` · `failed` · `skipped` · `timed_out` · `incomplete` (crash/killed/partial output) · `not_run`. The UI may summarise these as verified / unverified / stale / failed, but the stored record keeps the detail. `stale` is derived: evidence whose source or environment fingerprint no longer matches. Historical passes never imply current correctness.

## Execution rules
Separate from indexing and MCP-read. Tests are untrusted code: explicit per-run authorization, sandbox, scrubbed environment, network per mode (strict = fail closed if not enforceable), timeouts, captured output kept inside the storage boundary with secret scrubbing.

## Adapters (spec)
Interface: `discover(root) -> TestCommand[]`, `run(command, sandbox) -> Result`, `parse(result) -> TestCase[]`. v0.1 ships jest/vitest and pytest discovery; Playwright is an optional later adapter.

## v0.3 preview (not built now)
Coverage-based mapping tests↔symbols (evaluate existing selectors first), selection on change, recommend tests for uncovered risks, invalidate evidence via dependency edges.
