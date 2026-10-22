# Sentinel 3C report: controlled autonomous implementation, review and repair (non-executing)

Status: **IMPLEMENTED WITHOUT EXECUTION; gate not fully met.** No agent is launched and no agent-written or repository code is run (execution was not approved and no verified sandbox exists). Independent review: fresh Claude agents (the user accepted this in place of Codex on 2026-10-22).

## Built
- `sentinel/providers.ts`: detects Claude Code / Codex / local-model CLIs on PATH without running them; states hosted/network boundary; `launchProvider` always refuses; `reviewerIndependence` never treats two role labels as independence.
- `sentinel/worktree.ts`: authorized throwaway worktrees with a whole-tree baseline (full sha256, symlinks recorded, build dirs skipped only at the top level); detects out-of-scope changes, tampering with existing tests/test config/helpers/fixtures/policy and risky NEW config/mock/setup files or symlinks, and undeclared (concurrent) changes; enforcement fails the `scope` check, opens a blocking finding (withdrawing approvals) and pauses the task — it never overwrites. Re-authorizing an active worktree is refused; cancellation revokes it.
- `sentinel/findings.ts`: findings need verified evidence (latest failing machine evidence of the check, a required failing check, or a file+line in scope whose hash matches); blocking findings withdraw approvals; `fixed` needs new passing machine evidence on the current source (or, for tamper findings, the protected files restored); dispositions are decided once by a non-builder approver.
- `sentinel/repair.ts`: operator-started, capped budgets (iterations, wall-clock, tokens, cost, same-failure and distinct-failure limits), idempotent iteration keys, enforced backoff; exhaustion or recurrence BLOCKS the task.
- `sentinel/taskHandoff.ts`: task handoffs on the H4 handoff store; resume revalidates source, policy, scope and worktree.
- `tasks.ts`: `systemBlock` (revokes authority, drops queued work, clears the lease, bumps the capability epoch), `withdrawApprovals`, `recordTaskAct` (agent acts count for separation of duties), open blocking findings block eligibility.
- CLI: `sentinel providers | run (always refuses to launch) | worktree authorize|check [--declared] | review [add|--resolve] | repair start|record | task-handoff | resume | evidence`.

## Reviews
Security review (fresh Claude agent) found 12 confirmed issues (CLI not wired, large-file same-size edits, nested skip dirs, added files/symlinks, unprotected helpers/configs, re-authorization absorbing tampering, duplicate-finding crash, finding-evidence loopholes, tamper finding closable by an unrelated pass, systemBlock leaving lease/queue, caller-controlled repair budget, findings not withdrawing approvals); all fixed with regression tests. A separate test-quality review led to a hardening pass (see 3D/3E reports for the suite numbers).

## Not done / limits
Agents are run by the user, outside this tool; preventing (not just detecting) out-of-scope writes needs an OS sandbox. Pre-authorization edits are part of the baseline. Same human under two principal names is not detectable. Reviewer provider is an unverified claim.

## Verification
Full suite after integrating all parallel-agent work and fixes: **52 files, 670 tests passed, 0 failed**, typecheck clean, Node 22.23.3, macOS (`evidence/s3cde-vitest-verbose.txt`). An earlier run had one failure: the Foundation concurrency test T19 timed out under parallel load (42 s alone); its timeout was raised with a comment, then the suite was re-run.
