# Phase 2B — evidence-based implementation report

- **State:** PASS (with the caveats under "Known uncertainty"; the post-fix state was NOT re-reviewed by a fresh reviewer)
- **Repository / worktree / revision / dirty overlay:** local branch `phase-2a`, base `2c9c8426a7e8ded302a26413ff563f7374ca2ee5` (= origin/main), all Phase 2A + 2B work uncommitted (53 changed/untracked paths). Nothing was committed, pushed, merged or published.
- **Predecessor gate verified at:** Gate 0 PASS (`gate-0-report.md`); Phase 2A suite green before 2B started.
- **Implementation scope and exclusions:** dependency/structure graph (`docs/graph.md`): module, symbol and package edges, binding resolution through re-export chains, bounded traversal, impact, shortest path, cycles, stats, validation, CLI `engbrain graph`. Excluded: call graph (never produced), type-directed resolution, `node_modules`, incremental edge reuse (H5), MCP (2C).
- **Changed files (real paths):** `packages/core/src/{graphBuilder,graph,moduleResolver,moduleEdges,indexer,indexStats,freshness,queries,index}.ts`, `packages/core/src/adapters/typescript.ts`, `packages/core/src/store/{migrations,generations}.ts`, `packages/cli/src/{main.ts,commands/graph.ts,...}`, tests `tests/acceptance/p2b-graph.test.ts`, `tests/acceptance/p2b-review.test.ts`, `tests/helpers/graph-fixture.ts`, `packages/core/test/graphFacts.test.ts`, bench `tests/bench/index-bench.mjs`, docs `docs/graph.md`, `docs/code-intelligence.md`. Full list: `git status --short`.
- **Schema migrations and rollback/recovery evidence:** migration v3 (`graph_edges`, `graph_packages`, views, insert-only-while-building and immutability triggers), forward-only, with the pre-migration backup. Covered by `packages/core/test/migrations.test.ts` and the interrupted-publication tests in `p2b-graph.test.ts`.
- **Commands, APIs, supported languages/adapters:** `engbrain graph dependencies|dependents|path|cycles|impact|references|stats|validate`; core `traverse, shortestPath, findCycles, impact, references, graphStats, validateGraph, resolveNode`. TypeScript/TSX/JS/MJS/CJS via the existing tree-sitter adapters.
- **Test fixture IDs, actual commands and result counts:** `npx tsc -b && npx tsc -p tsconfig.test.json --noEmit && npx vitest run` (Node 22.23.3): 31 files, **386 passed, 0 failed, 0 skipped**. Verbose log: `evidence/2b-vitest-verbose.txt`.
  | Test / gate | Result | Evidence | Notes |
  |---|---|---|---|
  | p2b-graph (36 tests) | pass | verbose log | edges, resolution, traversal, impact, cycles, CLI, publication faults |
  | p2b-review (9 tests) | pass | verbose log | one regression per confirmed review finding (below) |
  | Foundation T1-T22, P2A | pass | verbose log | unchanged behaviour |
- **Clean-vs-incremental / branch isolation evidence:** clean and incremental indexing produce identical graph edges (p2b-graph determinism tests, seeded mutation runs from 2A extended to graph edges).
- **Security/egress/subprocess boundary observations:** no network calls (T7/T8 static + runtime guards still green); the only subprocess is hardened git; no repo code is executed. No OS sandbox exists.
- **Performance (measured, synthetic, macOS, Node 22.23.3 darwin-x64):** see `docs/graph.md`. 20,000 files: initial 36.2 s, unchanged re-index 2.7 s, one-file change 13.8 s (graph rebuild about 10.9 s), 242,842 edges, impact 92 ms, dependents depth 3 20 ms, DB 399 MiB, process peak 767 MiB. Before the review fixes, `impact` on a hub measured 41 s against a 500 ms budget.
- **Independent review:** a fresh read-only Claude agent (NOT Codex, same model family, so not a strict independent audit) reviewed the working tree and reported 12 confirmed findings plus some plausible ones. All confirmed ones were fixed, each with a regression test in `tests/acceptance/p2b-review.test.ts`:
  1. heritage/refs named by an enclosing scope's binding were resolved to the import (now lexical-scope aware, including arrow parameters, `for..of/in`, catch bindings, blocks);
  2. exponential `export *` lookup (shared ES resolve set + per-generation memo; 8^7-path fixture indexes in seconds);
  3. `impact` ignored its time/edge budgets (whole-run budgets, truncation reported);
  4. hot edge queries scanned the table (`INDEXED BY`, plan test);
  5. uncached binding resolution (memoised);
  6. package impact did not follow `DEPENDS_ON`;
  7. `export *` with an undecidable branch reported resolved (now unresolved/ambiguous with a reason);
  8. `CONTAINS/DEFINES/EXPORTS/CALLS` accepted by the CLI but never served (rejected with an explicit message; `validateGraph` flags them);
  9. `shortestPath` used name-match (`syntactic_only`) edges (excluded);
  10. `#` inside a file path broke symbol specs (last `#` separates);
  11. depth truncation flag was untruthful (now true only if edges remain);
  12. locale-dependent sort (plain comparison); `validateGraph` completeness (module edges vs syntactic references).
- **Known uncertainty, unsupported cases, risks, deviations:** (a) fixes were not re-reviewed by a fresh reviewer; (b) no wall-clock budget test (a timing assertion would be flaky); the edge budget is tested, the time budget only by the 41 s -> 92 ms measurement; (c) `var` hoisting out of nested blocks, `with`/`eval` are not modelled by scope tracking; (d) edges are rebuilt per generation (13.8 s one-file change at 20k); (e) 100k files untested, memory unmeasured; (f) macOS/Node 22 only, Linux/Windows/Node 24 untested; (g) benchmark data is synthetic.
- **Exit-gate reasons:** typecheck clean, 386/386 tests, confirmed review findings fixed with regressions, docs written, measurements recorded, no unsupported claims (graph is stated to be syntactic/potential-structural only).
- **Next phase ID and exact unmet prerequisites, if any:** 2C (read-only stdio MCP and context packets). Prerequisite: read `phases/02-phase-2c-context-and-mcp.md`; none unmet.
- **User approvals needed:** commit/push of all work (none authorized).
