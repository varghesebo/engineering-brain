# Impact, evidence import, test selection and handoffs (Phase H4)

Everything here is advisory or read-only context. Nothing executes repository code, nothing reaches the network, and no imported artifact can approve anything by itself.

## Evidence import (quarantine by default)
`engbrain evidence import <file> --format junit|lcov|cobertura|sarif|jest [--revision <commit> --run-command <cmd> --env k=v --verifier <id> --signature <hex>]`
- The artifact is parsed with a hardened reader first (XML: no DOCTYPE/ENTITY, depth 64, 500k nodes, 20 MiB; JSON size-capped); nothing is stored if parsing fails. All text (names, suites, rules, messages) is stripped of control and invisible formatting characters, clipped, and replaced when it looks like a secret. Only repository-relative paths are kept (absolute paths under the repo root become relative).
- **Trust.** An import is `quarantined` unless its HMAC-SHA256 signature verifies against a verifier registered with `engbrain evidence verifier add <id>` (admin; the key is shown once and kept in the 0600 `.engineering-brain/evidence-policy.json`) AND it declares a revision present in the history ledger, a command and an environment. The signature covers the artifact bytes plus format, revision, command, environment and verifier, so a genuine artifact cannot be re-labelled. An invalid signature can never be accepted. Otherwise only an operator with the verify role can `accept` it (a human decision) or `reject` it (final).
- **Standing** (computed at read, never stored): `applies`, `stale` (a bound file changed, the environment value changed, or the code left the revision the run used and the result cannot be shown unaffected), `unknown`, `out_of_scope` (revision not an ancestor of the checkpoint), `quarantined`, `rejected`. Evidence is never retroactively "passed".
- **Memory gate.** `memory verify` on CI-type records requires an artifact (by sha256) that is a signed or accepted, COMPLETE (not partial) import that still applies, in which the named test case of the named file passed (a skipped/failed/errored case of that name is not a pass).
- Failed, skipped, timed-out and errored results are recorded as such. Incomplete runs (declared counts that do not add up, a suite that failed to run, truncated input) are marked `partial` with warnings.
- Rows are immutable (triggers): only `trust` can be decided, a rejection is final, nothing is deleted.

## Impact (`engbrain impact <files…> | --since <commit>`, MCP `find_impacted_components`)
Classes: `direct_proven` (resolved edge, one hop), `transitive` (chain of resolved edges), `inferred_potential` (unresolved/ambiguous import whose name resembles a changed file). Inputs outside the index (deleted, excluded, unsupported) are listed as unknown. The repository-wide count of dynamic/unresolved/ambiguous imports and a missed-edge risk level (`low|medium|high`, with reasons; budgets, partial history and unknown inputs raise it) accompany every answer. Absence from the lists is absence of a recorded static edge, not independence.

## Advisory test selection (`engbrain tests select`, MCP `get_relevant_tests`)
Each test carries a proof class: `changed_test`, `imports_changed_file`, `imports_through_chain`, `imports_impacted_file`, `name_match` (heuristic). Changed or impacted files with no mapped test are returned as `unmapped` (UNKNOWN, not safe). `--sample n` adds a deterministic sample of unselected tests as a hedge; `selectionRecall()` compares a selection with a baseline's failing tests. Caps (300 targets, 500 tests) set `truncated` and push omitted files into `unmapped`.

## Handoff packets (`engbrain handoff create|show|list|close`, MCP `get_session_handoff`)
Immutable, compact (task, authorized scope paths, references, hypotheses labelled unverified, blockers, pending evidence, context-packet hash), bound to revision, generation, a fingerprint of the scope files' content hashes, and a policy hash. They read `stale` when a scope file or the evidence/approval policy changes, `expired` by time (default 24 h, max 7 d), `closed`/`superseded`. Overlapping active handoffs from another worktree/author are reported as conflicts and never merged; `usable` is false then. Only the author or an admin can close or supersede. A handoff is context, not an instruction.

## Limits and honest caveats
- A static import graph cannot see dynamic wiring, fixtures, config or shared state; selection and impact can miss tests (a seeded dynamic dependency in the acceptance test is reported as uncertainty and found only by the sample/baseline).
- Standing and handoff freshness are judged against the last published generation; the CLI and MCP warn when the index is stale.
- Local-token operator authentication and the local verifier key file do not stop a hostile process running as the same OS user.
- There is no verifier revocation yet (removing a key does not demote existing `signed` imports; reject them explicitly).
- An environment key that the evidence declares but the store never recorded cannot make the evidence stale.
- No execution sandbox exists; this phase never runs tests.
