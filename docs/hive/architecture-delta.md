# Hive vNext: architecture delta (Gate 0 audit and plan)

## Audit of the current checkout (2026-10-21, branch `main` = `origin/main` = 2c9c842)
| Area | State | Evidence |
|---|---|---|
| Foundation (Phase 1B) | **Implemented and green**: 207 tests, typecheck and build clean | `docs/foundation-deviations.md` |
| Schema | v1 only: `store_meta`, `generations`, `generation_extractors`, `generation_files`, `file_facts` | `store/migrations.ts` |
| Extractors | **Placeholder only** (`inventory`: language, size, line count). No parser, no symbols | `inventory.ts` |
| Git hardening | allowlist `rev-parse, ls-files, rev-list, symbolic-ref`; `-c` overrides; minimal env | `security/git.ts` |
| MCP / read API | **none** | |
| Platforms verified | macOS only (Node 22.23.3). Linux, Windows, Node 24: **not run** | |

Consequence: the Hive blueprint's "reuse existing content-addressed parsing" refers to infrastructure that is
only half there. The content-addressed fact store and generation publication exist; real parsing does not.

## Delta (what changes, in order)
1. **Wave 1a (prerequisite, deliberately small):** TS/JS syntax extractor (tree-sitter WASM, spike S1 decision):
   declarations, imports, requires, dynamic imports with literal-or-unknown targets. Migration v2 adds
   `symbols` and `syntax_refs`. Claims nothing about call resolution.
2. **Wave 1:** Git DAG ledger, per-commit change ledger, resume checkpoints, blob cache, refresh runs, lineage
   events, dirty-worktree overlay identity, `engbrain refresh`, `engbrain changes`, `changesSince` read API.
   Migration v3. `hardened git` allowlist gains `diff-tree`, `cat-file`, `merge-base`.
3. Waves 2-5 per `rollout.md`.

## Reuse, not rewrite
- Generations, manifests, content-addressed `file_facts`, the single-writer lock, atomic publish, GC, audit log,
  exclusion matcher, secret scanner and hostile-path handling are reused unchanged in behaviour.
- `indexRepository` is split into lock-acquiring wrapper + locked build so refresh can hold ONE lock across
  ledger ingestion and publication. Behaviour of `engbrain index` is unchanged (all 207 existing tests must stay green).
- One database. No parallel store.

## Migrations
Forward-only, with the existing pre-migration `VACUUM INTO` backup. v2: `symbols`, `syntax_refs`. v3: ledger
tables (see `commit-refresh-protocol.md`). Existing v1 manifests remain valid; the first `index`/`refresh` after
upgrade re-extracts because the extractor set (and therefore `extractor_set_hash`) changes.

## Non-goals for Wave 1
No MCP server, no feature graph, no evidence import, no LLM, no embeddings, no test execution, no network.
