# Phase H4 report: impact, evidence import, test selection, handoffs

Status: **PASS with disclosed limits** (nothing committed or pushed; all work is uncommitted on local branch `phase-2a`).

## Built
- Schema v7: evidence_imports / results / coverage / findings (immutable, no deletes, trust decided only quarantined|signed -> accepted|rejected), handoffs (immutable content, status only active -> superseded|closed).
- Hardened XML reader and importers: JUnit, LCOV, Cobertura, SARIF, jest JSON (`packages/core/src/evidence/`).
- Evidence store: quarantine by default, HMAC provenance policy (signature covers bytes + format, revision, command, environment, verifier), operator accept/reject, standing computed at read, CI gate in `memory verify`.
- Impact engine and advisory test selection with proof classes, unmapped = unknown, truncation flags, deterministic sampling, `selectionRecall` (`packages/core/src/impact/`).
- Handoff packets (`evidence/handoffs.ts`).
- MCP (read-only): `find_impacted_components`, `get_relevant_tests` (with proof), `get_verification_status`, `get_session_handoff`. CLI: `impact`, `tests select`, `evidence import|list|show|accept|reject|verifier add|status`, `handoff create|show|list|close`.
- Docs: `docs/impact-and-evidence.md`.

## Verification (actually run, Node 22.23.3, macOS)
- `npx tsc -b` and `npx tsc -p tsconfig.test.json --noEmit`: clean.
- Full suite after the review fixes: **41 files, 526 tests passed, 0 failed** (`evidence/h4-vitest-verbose.txt`).
- Acceptance coverage: forged/unsigned XML cannot verify memory; XXE/billion-laughs refused; failed/skipped/partial recorded; evidence stale on source and environment change; seeded dynamic dependency reported as uncertainty and found by the baseline sample; handoff expiry (scope, policy, time), conflicts across worktrees, ownership.

## Independent review (fresh read-only Claude agent; NOT Codex, not a strict audit)
11 confirmed findings, all fixed with regression tests: signature bound only to bytes (HIGH); unbound evidence never stale (HIGH); CI gate matched wrong test / jest absolute paths (HIGH); pre-import blocking signed import; silent truncation; incomplete runs not flagged partial; immutability trigger gaps; unsanitised artifact text and unvalidated labels; freshness warnings; handoff ownership; verifier-file lost update (now locked).

## Not done / disclosed
- The post-fix state was NOT re-reviewed by a second agent.
- No verifier revocation; an environment key never recorded cannot make evidence stale; local-token authentication does not stop a hostile same-user process.
- Impact/selection performance on large repositories was not benchmarked in this phase.
- Real Claude Code / Codex MCP handshake unverified. Linux, Windows, Node 24 untested. No execution sandbox; nothing runs repository code.
