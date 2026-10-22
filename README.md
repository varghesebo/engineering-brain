# engineering-brain

Privacy-first, local-first repository intelligence for AI coding agents. **Status: pre-release.** Foundation, Phase 2A
(code intelligence), 2B (dependency graph) and 2C (task context, read-only stdio MCP server, agent onboarding) are implemented;
commit history, memory and verification are not. See `docs/graph.md` and `docs/context-and-mcp.md`.
Licensed Apache-2.0.

## What works today (macOS, Node 22 verified; Linux, Windows and Node 24 are untested)
- `engbrain init | index | status | gc | uninstall`: a per-worktree SQLite store with content-addressed facts and atomically
  published, immutable generation snapshots; hardened git access; exclusions and secret scanning; a content-free audit log.
- **Code intelligence for TypeScript/JavaScript/JSX/TSX** (tree-sitter WASM behind a language-adapter interface): symbols with
  nesting, kinds, parameters, byte and line ranges; exports, default/anonymous exports, re-exports and CommonJS exports;
  imports, requires and dynamic imports (non-literal targets stay explicitly unknown); module relationships resolved per
  snapshot (relative, tsconfig paths/baseUrl, workspace packages), labelled resolved / external / unresolved / ambiguous / dynamic.
- Incremental updates: unchanged content is never re-parsed; clean and incremental indexing produce identical facts (tested).
- Queries from persisted data only: `engbrain symbols --file|--search|--kind|--exported`, `engbrain imports --file|--to`.
- `engbrain index --stats` (measured run statistics), `engbrain index --check` and `status` (freshness reported as
  heuristic / hash_verified / stale / unknown, never stronger than what was established).

Details, schema, resolver rules, measured benchmarks and limitations: `docs/code-intelligence.md`.

## Privacy, stated precisely
engbrain's own code makes no network calls (enforced by tests). It does **not** provide OS-level isolation for third-party code or
child processes, and it cannot control what hosted AI agents transmit. No source code, symbols or derived data leave the machine.

## Not implemented
Git commit/history intelligence, memory, verification/test execution, and any MCP tool that writes or executes. Linux, Windows and Node 24 are untested.
The Hive plan in `docs/hive/` is **paused**.

Requires Node.js 22.13+ (the SQLite native module needs it).

```
npm install --ignore-scripts
npm test          # builds, then runs the full suite
```
