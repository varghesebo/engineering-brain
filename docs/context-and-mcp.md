# Task context and the read-only MCP server (Phase 2C)

All of this reads the PUBLISHED index (one WAL snapshot per call). Nothing here writes to the repository or the store, executes repository code, or uses the network.

## Commands
- `engbrain context "<task>" [--max-tokens N] [--json]`: ranked, token-bounded packet for a task.
- `engbrain mcp [--fail-on-stale]`: stdio MCP server bound to this repository (`--root` selects it). stdout carries protocol messages only.
- `engbrain agents [--apply claude|codex]`: shows the exact config change; writes only with `--apply`.

## Search and ranking (`search.ts`)
Keyword search over indexed symbol names and file paths. Terms come from the query (identifiers kept whole and split on camelCase / snake_case, lower-cased, stop words dropped, at most 8).
Score = exact name 50, prefix 30, contains 15, qualified-name only 8, file stem equal 40, path contains 12 / 5, exported +5, +10 per extra matched term. Every hit lists `why`.
Order is total (score, path, line, key), so pages are deterministic. Cursors are bound to the query and generation: a cursor from another query, or from before an index update, is refused (`cursor expired`).
**Deviation from the pack text:** SQLite FTS5 is NOT used. `symbols` is WITHOUT ROWID (no external-content FTS) and a substring scan measured 97 ms p95 at 303k symbols; FTS5 is revisited at scale (H5). Only indexed files are searchable; excluded files (secrets, binaries, ignored) have no content hash and never appear.

## Context packet (`contextPacket.ts`)
Matches grouped into ranked files, then for the top three: direct dependencies/dependents (resolved module edges), test files that import them, and a short verified excerpt.
Excerpts are returned only if the file on disk still has the exact content hash the index recorded and the secret scanner passes the slice; otherwise a reason (`file_changed_since_index`, `withheld_by_secret_policy`, ...) and no text.
Evidence is separated from interpretation: the packet states what was found and where, never what to do; `uncertainty` lists what the index cannot decide (undecided imports, candidate caps, truncation).
**Token budget:** estimate = UTF-8 bytes / 3 (conservative, not a tokenizer). It is measured on the whole serialized packet including the metadata the server adds (freshness, snapshot), default 4,000, range 500-32,000. If it does not fit, parts are shed in a fixed order (excerpts, related files, tests, symbols, trailing files) and `budget.omitted` / `truncated` say so. `nextCursor` pages through further ranked files and always resumes after the last file actually returned (files shed for the budget are on the next page, never skipped); if the budget is too small for even one result the cursor does not advance and the packet says to raise `max_tokens`.

## MCP tools
`search_code`, `find_symbol`, `get_symbol_references`, `get_dependency_graph`, `get_feature_context`, `check_freshness(paths[])` (re-hashes up to 50 files), `get_relevant_tests` (discovery only: static import edges, or a name match labelled heuristic), `get_verification_status` (reports `not_available`: this build records no evidence and runs nothing).
Named-but-future tools (`find_impacted_components`, `retrieve_related_bugs`, `retrieve_architecture_decisions`, `get_memory_provenance`, `get_session_handoff`) are not listed; calling one returns an explicit `not_available` error, never invented data.
Every response carries `schemaVersion`, `generationId`, `revision`, `sourceFingerprint` (the indexed content state), `freshness` (level, basis, changed-file counts), `lastHashVerifiedAt`, `truncated`, `nextCursor`, `uncertainty`, an `UNTRUSTED_DATA` notice and per-item provenance (`extractionMethod`, `semanticCertainty`, `evidenceType`, extractor, content hash). Tree-sitter items are `syntactic_only`. Each tool has a hard response cap (errors included: messages are cut at 300 characters); lists are trimmed, `truncated` is set, and for paged tools (`search_code`, `get_feature_context`) the cursor is rebuilt to resume after the last item kept. For `get_feature_context` the caller's `max_tokens` (1,000-32,000) bounds the WHOLE response; the packet gets what remains after the envelope. `packet.budget.estimatedTokens` counts the packet only; the response-level `estimatedTokens` counts everything.
Field names are camelCase; docs/mcp-spec.md's snake_case names map one to one (`generationId` = `generation_id`, `sourceFingerprint` = dirty fingerprint, `lastHashVerifiedAt`, `nextCursor`). Provenance carries extractor id and version.
Freshness is the heuristic level (git file list + stat tuple), cached for 5 s except for `check_freshness` and under `--fail-on-stale`, which always recompute; it is never described as verified. `--fail-on-stale` turns a stale/unknown index into an error instead of a warning. Freshness is established first; the tool body then runs in ONE read transaction, so the header and the data always describe the same generation (if an index update landed in between, the response says so).

## Hardening (what is enforced and tested)
- Read-only: `Store.openReadOnly` opens SQLite read-only with `query_only`, never migrates or repairs, refuses a store needing migration, and applies the same ownership/root/symlink/tracked-by-git checks as the CLI. A copied store (different root) is refused. A test hashes the database and repository before and after tool calls.
- Bound to one repository: no tool accepts a repository or store argument.
- Every argument is validated against a closed schema first (unknown properties rejected, bounds, no control characters); paths must be repository-relative with no `..`, absolute, drive or backslash forms, and must be in the published index.
- Messages over 1 MiB are discarded and reported; batches and malformed JSON are rejected; errors come from a closed set of messages (no source text, SQL or file content).
- Excluded content (secrets, binaries, symlinks, ignored files) is absent from search, context, excerpts and errors (tested with a secret fixture); a path whose real location differs from its repository path (a symlink anywhere in the chain, including a parent directory swapped after indexing) is never read or hashed.
- Protocol: JSON-RPC 2.0, newline-delimited, versions 2025-06-18 / 2025-03-26 / 2024-11-05 negotiated. **No MCP SDK is used** (smaller trusted base: no new dependency, no HTTP stack); the transport and the tools/list, tools/call, ping and initialize methods are implemented directly and exercised by a real child-process client in the tests.
- The only subprocess is hardened git (freshness listing), as elsewhere; engbrain never executes the agents.

## Agent onboarding
`engbrain agents` detects `claude` / `codex` on PATH and their config locations WITHOUT executing them, so **agent versions are not checked**: review the diff. Claude Code: project `.mcp.json` (adds `mcpServers.engbrain` only if absent, preserves everything else, atomic write with re-parse check, refuses invalid JSON). Codex: appends a marked block to an existing `~/.codex/config.toml`, writing through a symlinked dotfile and keeping its permissions; never creates the directory; any spelling of an existing engbrain entry (bare/quoted table, dotted key, inline table) is left alone; non-object JSON is refused. The entry holds absolute paths of this machine, so do not commit `.mcp.json`. The entry launches `node <this install's bin.js> mcp --root <repo>` with absolute paths.

## Measured (synthetic TypeScript repositories, macOS, Node 22.23.3 as darwin-x64)
Task "change fn<N>_0 in Cls<N>" (one symbol). Baseline = one in-process pass that reads every file and substring-searches the same words (a lower bound for an unassisted search; warm cache).
| Files | `get_feature_context` p50 / p95 | `search_code` p95 | Packet size | First file correct | Baseline scan | Tokens if baseline files were read |
|---|---|---|---|---|---|---|
| 2,000 | 18 / 26 ms | 12 ms | 1,243 tokens, 1 file | yes | 109 ms, 2,051 files, 3 matches | about 638,000 |
| 20,000 | 331 / 343 ms | 223 ms | 1,297 tokens, 1 file | yes | 1,071 ms, 20,051 files, 3 matches | about 6,504,000 |
Retrieval calls: 1 for both. NOT measured: a real agent session, token savings in practice, time-to-first-relevant-file for a person or model, cold cache. A plain grep also finds the 3 matching files in one call; the packet adds ranking, dependencies, tests and a verified excerpt.

## Not verified
- **Claude Code and Codex integration:** no real handshake was run. Codex is not installed here; a Claude Code client exists on this machine, but starting it would call its API (network), which was not authorised. The protocol is validated only against the project's own stdio client. Treat integration as UNVERIFIED.
- Linux, Windows, Node 24.
- Packet quality on real repositories (ranking is keyword based; synthetic names are unusually distinctive).
