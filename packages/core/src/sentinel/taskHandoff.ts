import type Database from "better-sqlite3";
import { EngbrainError } from "../errors.js";
import { createHandoff, showHandoff } from "../evidence/handoffs.js";
import type { Actor } from "../memory/operators.js";
import { listFindings } from "./findings.js";
import { policyHash, requiredChecks } from "./policy.js";
import { checkStanding, getTask } from "./tasks.js";

/**
 * Task handoffs: a compact packet a NEW coding session can resume from without re-reading the repository. It reuses the H4 handoff store (immutable, scoped, expiring, conflict-aware) and adds the
 * task's state, open findings and the checks still pending. Resuming REVALIDATES the source fingerprint and the policy: a stale packet is refused, never trusted.
 */
const normScope = (scope: readonly string[]): string[] => [...new Set(scope.map((s) => s.replace(/\/$/, "") || s))].sort();
const sameScope = (a: readonly string[], b: readonly string[]): boolean => JSON.stringify(normScope(a)) === JSON.stringify(normScope(b));

export function createTaskHandoff(db: Database.Database, storeDir: string, id: string, actor: Actor, currentFingerprint: string, now?: Date): string {
  const task = getTask(db, id);
  if (currentFingerprint !== task.source_fingerprint) {
    throw new EngbrainError("POLICY_REFUSED", "the source changed since the task's fingerprint: refresh the task before writing a handoff");
  }
  const scope = JSON.parse(task.scope_json) as string[];
  const pending = requiredChecks(storeDir, task.profile, scope).filter((c) => checkStanding(db, storeDir, id, c, currentFingerprint, now).blocker !== null);
  const open = listFindings(db, id, { open: true });
  const h = createHandoff(db, storeDir, {
    task: `${task.title} [${task.state}]`.slice(0, 500), scope: normScope(scope), references: [`task:${id}`, ...open.map((f) => `finding:${f.finding_id}`)].slice(0, 20),
    blockers: [...(task.blocked_reason === null ? [] : [task.blocked_reason.slice(0, 280)]), ...open.map((f) => `open ${f.severity} finding: ${f.title.slice(0, 200)}`)].slice(0, 20),
    pendingEvidence: pending.map((c) => `check pending or failing: ${c}`).slice(0, 20)
  }, { actor, ...(now === undefined ? {} : { now: () => now }) });
  return h.handoff_id;
}

export interface ResumeView { taskId: string; state: string; revision: number; checkpoint: unknown; openFindings: Array<{ id: string; severity: string; title: string }>; pendingChecks: string[]; handoffStanding: string }

export function resumeFromHandoff(db: Database.Database, storeDir: string, handoffId: string, taskId: string, currentFingerprint: string, now?: Date): ResumeView {
  const view = showHandoff(db, storeDir, handoffId, now === undefined ? {} : { now: () => now });
  if (view === null) {
    throw new EngbrainError("INVALID_ROOT", "no such handoff");
  }
  const task = getTask(db, taskId);
  // a task handoff names exactly one task, first (as createTaskHandoff writes it), and covers exactly the task's scope
  const taskRefs = view.references.filter((r) => r.startsWith("task:"));
  if (view.references[0] !== `task:${taskId}` || taskRefs.length !== 1) {
    throw new EngbrainError("POLICY_REFUSED", "this handoff is not for that task");
  }
  if (!sameScope(view.scope, JSON.parse(task.scope_json) as string[])) {
    throw new EngbrainError("POLICY_REFUSED", "the handoff's scope does not match the task's scope: it cannot be resumed");
  }
  const worktree = db.prepare("SELECT status FROM sentinel_worktrees WHERE task_id = ?").get(taskId) as { status: string } | undefined;
  if (worktree !== undefined && worktree.status !== "active") {
    throw new EngbrainError("POLICY_REFUSED", "the task's worktree authorization was revoked: it cannot be resumed");
  }
  if (view.standing !== "current") {
    throw new EngbrainError("POLICY_REFUSED", `the handoff is ${view.standing} (${view.reasons.join("; ")}): it cannot be resumed`);
  }
  if (task.source_fingerprint !== currentFingerprint) {
    throw new EngbrainError("POLICY_REFUSED", "the source fingerprint changed: the task must be refreshed before it can be resumed");
  }
  if (task.policy_hash !== policyHash(storeDir)) {
    throw new EngbrainError("POLICY_REFUSED", "the policy changed since the task was created: it must be re-planned");
  }
  if (["FAILED", "CANCELLED"].includes(task.state)) {
    throw new EngbrainError("POLICY_REFUSED", `the task is ${task.state}`);
  }
  const scope = JSON.parse(task.scope_json) as string[];
  return {
    taskId, state: task.state, revision: task.revision, checkpoint: task.checkpoint_json === null ? null : JSON.parse(task.checkpoint_json),
    openFindings: listFindings(db, taskId, { open: true }).map((f) => ({ id: f.finding_id, severity: f.severity, title: f.title })),
    pendingChecks: requiredChecks(storeDir, task.profile, scope).filter((c) => checkStanding(db, storeDir, taskId, c, currentFingerprint, now).blocker !== null), handoffStanding: view.standing
  };
}
