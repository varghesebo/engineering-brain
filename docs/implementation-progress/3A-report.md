# Sentinel 3A report: orchestration, policy and evidence-integrity foundation

Status: **IMPLEMENTED, REVIEW-LIMITED.** The pack says an unresolved required independent review of high-assurance authorization/evidence code is a BLOCKER. Codex is unavailable; the only review was by a fresh read-only Claude agent (NOT Codex, not a strict independent audit) and the post-fix code was not re-reviewed. Treat 3A as functionally complete but not cleared by the pack's independence requirement. Nothing committed or pushed.

## Built
- Schema v8: tasks (seal, lease hash, capability epoch, base revision), hash-chained + MAC-signed events and evidence, MAC-signed approvals and execution authorizations, work queue; append-only/immutability triggers.
- `packages/core/src/sentinel/`: `policy.ts` (internal profiles A1-A4, stricter-only local policy, risk scoring adds checks), `capabilities.ts` (role tokens, epoch revocation), `tasks.ts` (16-state machine, evidence, eligibility, assurance, approval, revalidation, lease, checkpoints, queue, cancel, report), `execution.ts` (sandbox self-test, per-task execution authorization, synthetic worker, path confinement), `fingerprint.ts`.
- CLI: `sentinel plan [--dry-run] | list | status | report | approve | authorize | revalidate | check-scope | capability issue | cancel`.

## Verification (run, Node 22.23.3, macOS): typecheck clean; full suite **43 files, 543 tests passed, 0 failed** (`evidence/s3a-vitest-verbose.txt`). An earlier run of the same day had 2 failures (a capability-expiry slip in my own test, and the offline guarantee test that did not yet allow the Sentinel execution module as a `child_process` user); both were fixed and the suite rerun before this was recorded.
Covers: illegal transitions and crash resume; failed/pending checks and out-of-scope changes force BLOCKED; builder/verifier/approver separation; forged evidence (fingerprint, verifier, origin, timestamp, raw edits, replacement, truncation, forged approval rows); stale authorization on source/policy/new evidence; execution authorization state-gated, single-use, expiring; strict mode with no sandbox; real macOS sandbox denies writes; cancellation (in-process and from another connection); concurrent-controller and stale-revision refusal; CLI.

## Independent review (fresh Claude agent, not Codex): 19 confirmed findings; fixed
requester/approver/builder separation, role-owned review checks, evidence state gating, lease secret token, single cancel path revoking authority, authority revoked on BLOCKED/FAILED, evidence-head-bound approvals, scope check mandatory, MAC on events/approvals/authorizations plus task seal (state edits and truncation detected), replace-insert guard, queue completion/requeue, DoS caps, malformed policy file, sandbox probed inside the worker, cross-process cancel polling, hash-verified index for source-binding commands, cancel allowed on stale index.

## Not done / disclosed limits
- Same human under two different principal names cannot be detected; no identity-to-principal mapping.
- MAC key is a same-user 0600 file: roles separate duties inside the API, not an OS boundary; core functions trust the caller's fingerprint.
- Scope check covers committed changes only (uncommitted edits are not listed); `confinePath` exists but no repository-code runner uses it yet.
- Sandbox: only file-write denial is probed (network denial is in the profile, not probed); no CPU/memory limits; macOS only. No arbitrary repository code can run; only fixed synthetic programs.
- No multi-process race test (atomicity is by immediate transactions and single-connection tests); no overrides/escalation routing (every check non-waivable).
- Linux/Windows/Node 24 untested.
