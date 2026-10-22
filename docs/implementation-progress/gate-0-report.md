# Gate 0 — evidence-based report (Phase 2A verification)

- **State:** PASS (with the caveats listed below)
- **Repository / worktree / revision / dirty overlay:** `~/Documents/Project/engineering-brain`; local branch `phase-2a` (created from `main` before this pack was read); HEAD `2c9c8426a7e8ded302a26413ff563f7374ca2ee5` = `origin/main`; **working tree dirty: all Phase 2A work is uncommitted** (42 changed/untracked entries). Source tree fingerprint `99b3d9e53817c9d485f57dd52dfc9d2eede9d7f1b73a44862d7829a58cd3ea6b` (125 files; method in `gate-0-capabilities.json`).
- **Predecessor gate verified at:** n/a (first gate).
- **Honest note on provenance:** the pack describes Gate 0 as auditing an *existing* Phase 2A. Phase 2A did not exist as committed code: it was implemented in this same session (uncommitted) and is verified here by running its tests. The audit rule "do not edit application code" therefore applied to Gate 0's own assessment; defects found by the independent review earlier in the session were fixed before this verdict.
- **Implementation scope and exclusions:** Phase 2A only. Not built: graph schema, traversal/impact, context packets, MCP, commit ledger, memory, Sentinel, sandboxed execution.
- **Changed files:** see `git status` on branch `phase-2a`; new core modules `adapters/typescript.ts`, `codeExtractor.ts`, `defaultExtractors.ts`, `extractor.ts`, `factWriter.ts`, `contentPolicy.ts`, `candidates.ts`, `moduleResolver.ts`, `moduleEdges.ts`, `indexStats.ts`, `freshness.ts`, `queries.ts`, `symbolCorrelation.ts`; CLI `symbols`, `imports`, `index --stats/--check`, richer `status`.
- **Schema migrations and rollback/recovery evidence:** forward-only v2 (content-derived code facts) and v3 (extractor applicability, `module_edges`, views `applicable_facts` and `symbol_occurrences`), pre-migration `VACUUM INTO` backup; test `packages/core/test/migrations.test.ts` proves a v1 store keeps its generations, manifests and facts after upgrade and that the backup holds the pre-upgrade state. A newer-schema store is refused.
- **Commands/APIs/languages:** `engbrain init|index [--stats|--check]|status [--check]|symbols|imports|gc|uninstall`; TS, TSX, JS, JSX, ESM, CommonJS via tree-sitter WASM behind a `LanguageAdapter` interface.
- **Test fixture IDs, actual commands and result counts:**
  `npx tsc -p tsconfig.test.json --noEmit` (exit 0); `npx tsc -b` (clean); `npx vitest run --reporter=verbose` on Node v22.23.3:
  | Gate | Result | Evidence | Notes |
  |---|---|---|---|
  | Full suite | **331 passed, 0 failed, 0 skipped** (28 files) | `evidence/gate-0-vitest-verbose.txt` | macOS only |
  | Nested/duplicate symbols | pass | `p2a-code-intelligence.test.ts`, `codeExtractor.test.ts` | |
  | Imports/re-exports/barrels/aliases/workspaces | pass | `p2a-code-intelligence.test.ts`, `moduleResolver.test.ts` | |
  | Malformed TSX (and TS) | pass | `p2a-code-intelligence.test.ts` ("Gate 0 fixture: malformed TSX") | |
  | Excluded secrets | pass | `t12-secrets.test.ts`, `p2a-code-intelligence.test.ts` | scanner has documented false negatives |
  | Rename / delete | pass | `p2a-code-intelligence.test.ts` | |
  | Branch switch / dirty overlay | pass | `t03-t04-snapshots.test.ts`, `p2a-code-intelligence.test.ts` | |
  | Interrupted generation | pass | `t05-t19-crash-and-concurrency.test.ts` (in-process faults + real SIGKILL) | |
  | No-change refresh | pass | `p2a-code-intelligence.test.ts` (parses 0 files, same generation) | |
  | Clean == incremental | pass | 12 seeded mutation runs in `p2a-code-intelligence.test.ts`; 20 in `t01-t02` | |
  | No network from own code | pass | `t07-t08-offline.test.ts` (static + in-process guard) | does not cover native addons or child processes |
- **Clean-vs-incremental / branch isolation evidence:** as above; stale index after a branch switch is reported `stale`, and re-indexing removes the other branch's symbols.
- **Security/egress/subprocess boundary observations:** only subprocess is hardened git (allowlisted read-only subcommands). No OS isolation exists. Review findings fixed: path-dependent fact poisoning, terminal-control injection, workspace-package shadowing, unverified config files, unbounded resolution cost.
- **Performance and token measurements (measured only):** 20,000 synthetic files: initial 23.1 s (864 files/s), unchanged re-index 2.62 s, one-file change 4.42 s (1 file parsed), DB 276.7 MiB, peak RSS 244 MiB, symbol search p95 93 ms. Token measurements: none taken (no retrieval layer yet). Table in `docs/code-intelligence.md`.
- **Independent review:** **Codex unavailable.** A separate Claude agent reviewed read-only (same model family; not a Codex review, not a strict independent audit). 15 confirmed findings, all fixed and re-tested; some "plausible" items recorded as limitations.
- **Known uncertainty, unsupported cases, risks, deviations:** macOS/Node 22 only (Linux, Windows, Node 24 untested); syntax-level facts only; single-threaded parsing; every index run re-hashes all files; substring symbol search (no FTS5); resolver has no `node_modules` lookup or package `exports` conditions; benchmark is TypeScript-only synthetic data; `tree-sitter-typescript` has an install script (install with `--ignore-scripts`).
- **Exit-gate reasons:** all mandatory Gate 0 criteria executed and passed on the supported (macOS) platform; no outstanding approvals; no unauthorized actions taken.
- **Next phase ID and exact unmet prerequisites:** 2B — none blocking.
- **User approvals needed:** none for 2B as scoped (a new SQLite migration inside the existing store, no new dependencies expected). Still required before ANY commit/push: explicit approval (all work remains uncommitted).
