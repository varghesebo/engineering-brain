# MCP interface

Transport: **local stdio only** in v0.1 (no HTTP listener). Remote transport later requires authentication and per-repository authorization. Protocol and CLI versioned; capability negotiation at initialize; server reports `schema_version` and supported tool set.

## Read-only tools
| Tool | v0.1 | Notes |
|---|---|---|
| `search_code` | yes | FTS5 over symbols/files; returns references, not file bodies |
| `find_symbol` | yes | |
| `get_symbol_references` | yes | edges with `proof_type` |
| `get_dependency_graph` | yes | bounded depth |
| `get_feature_context` | yes | context-budget governor assembles result |
| `get_relevant_tests` | discovery only | name/path match, no graph selection claim |
| `get_verification_status` | yes | passed/failed/skipped/timed_out/incomplete/not_run, bound to fingerprints |
| `check_freshness(paths[])` | yes | re-hashes up to N named files; lets an agent confirm just before relying on them |
| `find_impacted_components` | v0.3 | |
| `retrieve_related_bugs`, `retrieve_architecture_decisions`, `get_memory_provenance`, `get_session_handoff` | v0.2 | |

No MCP tool writes memories, runs tests, or modifies files. Those are CLI-only behind explicit authorization.

## Every response includes
`generation_id`, `revision`, `dirty_fingerprint`, `freshness` (`hash_verified|heuristic|stale|unknown`) with `basis` and `last_hash_verified_at`, `truncated`, `next_cursor`, per-item provenance (`extraction_method`, `semantic_certainty`, `evidence_type`, extractor id/version, source file+range, `content_hash`), and an `uncertainty` note when context is incomplete. Tree-sitter-derived items are `syntactic_only` and never presented as resolved call targets.

## Input/output hardening (OWASP MCP guidance)
Schema-validate all inputs; canonicalize and root-confine paths; reject symlink escapes; cap result size/page; strip/label repository text as untrusted data; no cross-repository access (server bound to one `repository_id`); access control enforced in the server, not by agent instructions; diagnostics never include source content.

## Agent onboarding (CLI: `engbrain agents`)
Detect Claude Code and Codex and their installed versions; validate compatibility against a tested-version table (unknown versions => warn, print the config for manual review rather than writing a brittle snippet);  show a diff of the proposed minimal MCP config; apply only on approval; never overwrite existing config or instructions (append-only, marked block); offer `CLAUDE.md`/`AGENTS.md` snippets that reference the tool rather than copy contents; version/capability check; integration test launches the server from each agent against a synthetic repo and verifies a bounded response.
