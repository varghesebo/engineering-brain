# Phase H1 — evidence-based implementation report

- **State:** PASS (macOS / Node 22 only). The post-fix state was NOT re-reviewed by a fresh reviewer.
- **Repository / revision:** local branch `phase-2a`, base `2c9c8426a7e8ded302a26413ff563f7374ca2ee5`, everything since uncommitted. Nothing committed, pushed, merged or published.
- **Predecessor gate:** 2C (`2C-report.md`), with the real-client MCP handshake still UNVERIFIED.
- **Scope:** hardened read-only Git DAG walker, commit ledger (migration v4), per-blob fact reuse, lineage/checkpoints, atomic publication with the working-tree generation, exact dirty overlay, `changesSince`, CLI `refresh | history | changes`. Excluded: MCP exposure, memory, behavioural claims, a combined-merge view.
- **Changed files (new):** `packages/core/src/history/{gitHistory,ledger,overlay,refresh,changes}.ts`; migration v4 (`store/migrations.ts`), hooks in `indexer.ts` and `store/generations.ts`, ledger-aware `store/gc.ts`; `packages/security/src/git.ts` (4 new allowlisted subcommands, `runBuffer`, more forbidden arguments, hardening flags); `packages/cli/src/commands/refresh.ts`; tests `tests/acceptance/{h1-ledger,h1-ledger-2,h1-review}.test.ts`, helpers `dag-fixture.ts`, `h1.ts`, `refresh-kill.mjs`; `tests/bench/history-bench.mjs`; docs `docs/history.md`, `docs/hive/commit-refresh-protocol.md`.
- **Tests** (`npx tsc -b && npx tsc -p tsconfig.test.json --noEmit && npx vitest run`, Node 22.23.3): 35 files, **435 passed, 0 failed, 0 skipped**; log `evidence/h1-vitest-verbose.txt`.
  | Gate | Result |
  |---|---|
  | H1-1 commit fidelity (A..E, two-parent merge, per-parent changes, renames, rename candidate) | pass |
  | H1-2 rebase/force-push (rewrite, fork, orphans excluded, no re-extraction) | pass |
  | H1-3 shallow clone (partial, boundary commits, unknown ancestors) and base_missing | pass |
  | H1-4 blob reuse across commits and branches (counters) | pass |
  | H1-5 stepwise equals one-shot ledger; published generation equals a clean index | pass |
  | H1-6 fault injection at 8 points and SIGKILL at 5 points: readers stay on the previous checkpoint, resume equals the uninterrupted run; cancellation; budgets | pass |
  | H1-7 worktree overlays separate, clean tree has none | pass |
  | H1-8 rename accuracy / ambiguity | pass |
  | H1-9 secrets, sensitive paths, symlinks, submodules | pass |
  | H1-10 hostile config (diff.external, textconv, filters, fsmonitor, pager, ssh, gpg, hooks, replace refs, alternates, core.worktree) | pass |
  | H1-11 memory poisoning (subjects) | pass |
  | H1-12 offline (network guard, zero attempts) | pass |
  | H1-13 branch correctness | pass |
  | Review regressions (9 tests) | pass |
- **Security:** hostile-config test found a real hole in my first overlay design (`ls-files --modified` runs a repository clean filter); replaced by content-hash comparison against `cat-file` blobs. No `log`, no pager, no external diff, no hooks, no lazy fetch, replace refs and commit-graph ignored; alternates refused; `core.worktree` repos are not treated as git repos.
- **Measured (synthetic):** 300 commits x 200 files: baseline 1.4 s; backfill 28.1 s (11 commits/s, 1,094 changes, 1,294 symbol deltas, 894 blobs parsed once); no-op refresh 0.5 s; dirty refresh 0.55 s; DB 5.5 MiB; peak RSS 148 MiB. Not measured: 100k+ commits, huge commits, cold cache, other platforms.
- **Independent review:** fresh read-only Claude agent (NOT Codex; not a strict audit). 8 confirmed findings, all fixed with regression tests: (1) no-op refresh erased the overlay, (2) invented symbol deltas when a side is excluded, (3) unshallow left boundary commits empty yet history "complete", (4) unpublished runs visible to readers (lineage, orphan count, commit lookups, stale `running` runs), (5) legal git paths silently dropped, (6) overlay under eol/filters (documented as raw-bytes basis, not fixable without git's conversion), (7) invisible Unicode in subjects, (8) opaque maxBuffer failure that could wedge a refresh. Plausible items handled: batch memory bound, hashes only for read-eligible sides, no caching of `missing_object`, overlay size cap, lineage branch source, `core.commitGraph=false`, `diff.renameLimit`, `GIT_NO_LAZY_FETCH`.
- **Known uncertainty:** (a) no re-review after fixes; (b) overlay basis is raw bytes (can show dirty under eol attributes); (c) `changesSince` cost grows with ledger size (H5); (d) per-commit `diff-tree` process limits throughput; (e) promisor/partial clones error rather than fetch; (f) backfill is oldest-first with no "recent N" horizon; (g) Windows/Linux/Node 24 untested.
- **Next phase:** H2 (feature intelligence). **User approvals needed:** commit/push (none authorised).
