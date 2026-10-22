# Phase H3 — evidence-based implementation report

- **State:** PASS (macOS / Node 22 only). The post-fix state was NOT re-reviewed by a fresh reviewer.
- **Repository / revision:** local branch `phase-2a`, base `2c9c8426a7e8ded302a26413ff563f7374ca2ee5`, everything since uncommitted. Nothing committed, pushed, merged or published.
- **Predecessor gate:** H2 (`H2-report.md`); feature graph and Git history operational.
- **Scope:** bitemporal, append-only, evidence-backed memory (migration v6): records of eight kinds with evidence objects, pointers bound to content hashes, invalidation predicates, applicability by branch lineage, supersession, rejected approaches, fix/bug rules, operator-authenticated CLI writes, read APIs (`memory search|show|stale|summary|env|export|gc`, `bugs related`, `decisions related`, `evidence provenance`) and four read-only MCP tools. Excluded: any MCP write, any model call, cross-worktree sharing, stronger-than-local operator identity.
- **Changed files (new):** `packages/core/src/memory/{operators,records,evaluate,queries,prepared}.ts`; migration v6; `reachableFrom` export; `packages/cli/src/commands/memory.ts`; the four tools in `packages/cli/src/mcp/tools.ts`; tests `tests/acceptance/h3-memory.test.ts` (and the tool-list assertion in `p2c-context-mcp.test.ts`); bench `tests/bench/memory-bench.mjs`; docs `docs/memory.md`.
- **Tests** (`npx tsc -b && npx tsc -p tsconfig.test.json --noEmit && npx vitest run`, Node 22.23.3): 39 files, **506 passed, 0 failed, 0 skipped**; log `evidence/h3-vitest-verbose.txt`.
  | Gate | Result |
  |---|---|
  | Bug at A, fix at B, regression verified at C, dependent symbol changes at D: verification stale, warned, excluded by default | pass |
  | Observed vs effective validity across late CI results, supersession windows, immutability; deleted test and environment update invalidate; unrecorded environment is unknown | pass |
  | Model memory never authoritative; substantiation rules; unknown proof stays unknown; other branch not contaminated; dirty overlay judged and warned | pass |
  | Fix rules (incident or failing test + ledger commit), rejected approaches keep reason and dates, retention/GC, secrets refused and withheld | pass |
  | Token-bounded queries with evidence paths, identical after restart, compact summaries | pass |
  | README / commit message / record body cannot approve or change policy; operator authentication; MCP has no write | pass |
  | Review regressions (13 confirmed findings plus storage guards) | pass |
- **Security/privacy:** writes need an authenticated operator (token hash only, 0600 file, serialised updates); MCP and repository text can never write; every stored string is secret-scanned at write and export; no network, no model, no source text stored. Stated limit: local token authentication does not stop a hostile process running as the same OS user.
- **Measured (synthetic):** 10,000 records: 4,300 writes/s, search p95 33 ms, summary 25 ms, DB 11 MiB, peak RSS 290 MiB. Details in `docs/memory.md`.
- **Independent review:** fresh read-only Claude agent (NOT Codex; not a strict audit): 13 confirmed defects, all fixed with regression tests (listed in `docs/memory.md`); plausible items handled.
- **Known uncertainty:** (a) no re-review after fixes; (b) invalidation is file-granular (symbol checks add existence and signature); (c) local-token authentication only; (d) a record that went stale after an evidence change stays unusable until re-recorded; (e) branch lineage needs the ledger (`engbrain refresh`); (f) macOS/Node 22 only.
- **Next phase:** H4 (impact, evidence, handoff). **User approvals needed:** commit/push (none authorised).
