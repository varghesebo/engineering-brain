# Upstream audit

Clones are untrusted reference data in `~/Documents/Project/engineering-brain-upstream/<name>/` (shallow, never executed). Verified 2026-10-21 from the LICENSE files in each clone.

| Project | Commit audited | License (from LICENSE file) | Reuse class | Decision |
|---|---|---|---|---|
| GitNexus | `ab0b03846da74f1b17ff245246570febfe743559` | PolyForm Noncommercial 1.0.0 | **Architecture/reference study only** (requires permission for anything more) | Copy no code. Independently implement. Ideas studied: tree-sitter parsing, per-repo `.gitnexus/` index, MCP tool surface. |
| Graphiti | `8e320f880e7d169a907dbf2a7ac4188586c03b55` | Apache-2.0 (also `pyproject.toml`) | **Architecture/reference study only** for now | Needs Neo4j/FalkorDB/Neptune and, by default, an LLM + embedding API. Violates "no mandatory graph DB / offline". Borrow the bi-temporal fact model and provenance idea for v0.2. Not a dependency. |
| SCIP | `fcb3cb3c679fe2da18141550f864b9e67afab297` | Apache-2.0 | **Thin adapter / permissible dependency** | Consume `.scip` protobuf output; per-language indexers (scip-typescript, scip-python, ...) are optional external tools. |
| tree-sitter | `e3d578032dec2e7042291864302714878315dbed` | MIT | **Permissible direct dependency** | Parsing for TS/JS in v0.1 via adapters. |

## Still to verify before v0.1 (do not assume)
- Transitive licenses of chosen npm packages (`better-sqlite3`, `tree-sitter` grammars, MCP SDK, protobuf lib) via automated scan; record in `NOTICE` and the SBOM.
- Maintenance/activity of each SCIP per-language indexer individually (the SCIP README does not state it).
- Whether SCIP indexers run offline without fetching dependencies (some invoke package managers); if not, adapter is optional and tree-sitter is the baseline.
- Coverage-based test selectors and LSP options: evaluated for v0.3, not v0.1.

## Rules
- Public visibility is not permission. Nothing from GitNexus enters this repo.
- Re-run this audit (new SHAs, licenses) before each release.
