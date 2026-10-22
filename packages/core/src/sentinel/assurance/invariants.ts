import { createHash, randomUUID } from "node:crypto";
import type Database from "better-sqlite3";
import { EngbrainError } from "../../errors.js";
import { requireRole, type Actor } from "../../memory/operators.js";
import { findSecretIn } from "../../memory/records.js";
import { assertCanApprove, getTask } from "../tasks.js";

/**
 * Approved invariants: statements a human approver (never the builder, never an agent role on the task) commits to, stored with the SHA-256 of their text. The store refuses any later edit or
 * delete; a change is a NEW invariant that supersedes the old one. Candidate tests are derived as plain text and never alter the invariant.
 */
export const INVARIANT_KINDS = ["idempotency", "ledger_balance", "monotonic_state", "acl_denial", "custom"] as const;
export type InvariantKind = (typeof INVARIANT_KINDS)[number];

export interface InvariantRow { invariant_id: string; task_id: string; kind: InvariantKind; statement: string; statement_sha256: string; approved_by: string; approved_at: string; supersedes: string | null }
export interface InvariantInput { kind: InvariantKind; statement: string; supersedes?: string }
export interface CandidateTest { name: string; invariantId: string; statementSha256: string; style: "example" | "property" | "negative"; spec: string }

const sha = (s: string): string => createHash("sha256").update(s).digest("hex");
const statementText = (v: string): string => {
  const t = v.trim();
  if (t.length < 1 || t.length > 2000 || /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(t)) {
    throw new EngbrainError("POLICY_REFUSED", "an invariant statement must be 1-2000 characters without control or invisible formatting characters");
  }
  if (findSecretIn({ t }) !== null) {
    throw new EngbrainError("POLICY_REFUSED", "the invariant looks like it contains a secret");
  }
  return t;
};

/** Approves an invariant for a task. Only an approver who did not build the task and never acted as an agent role on it may approve; `supersedes` must name a current invariant of the same task. */
export function approveInvariant(db: Database.Database, taskId: string, input: InvariantInput, actor: Actor, now?: Date): InvariantRow {
  requireRole(actor, "approve");
  if (!INVARIANT_KINDS.includes(input.kind)) {
    throw new EngbrainError("POLICY_REFUSED", `invariant kind must be one of: ${INVARIANT_KINDS.join(", ")}`);
  }
  const statement = statementText(input.statement);
  const id = `inv_${randomUUID().replace(/-/g, "").slice(0, 16)}`;
  return db.transaction((): InvariantRow => {
    assertCanApprove(db, getTask(db, taskId), actor.id);
    if (input.supersedes !== undefined) {
      const old = db.prepare("SELECT task_id FROM sentinel_invariants WHERE invariant_id = ?").get(input.supersedes) as { task_id: string } | undefined;
      if (old === undefined || old.task_id !== taskId) {
        throw new EngbrainError("POLICY_REFUSED", "an invariant can only supersede an existing invariant of the same task");
      }
      if (db.prepare("SELECT 1 FROM sentinel_invariants WHERE supersedes = ?").get(input.supersedes) !== undefined) {
        throw new EngbrainError("POLICY_REFUSED", "that invariant was already superseded: supersede its successor");
      }
    }
    db.prepare("INSERT INTO sentinel_invariants (invariant_id, task_id, kind, statement, statement_sha256, approved_by, approved_at, supersedes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
      .run(id, taskId, input.kind, statement, sha(statement), actor.id, (now ?? new Date()).toISOString(), input.supersedes ?? null);
    return db.prepare("SELECT * FROM sentinel_invariants WHERE invariant_id = ?").get(id) as InvariantRow;
  }).immediate();
}

/** A task's invariants: current (not superseded) ones first, newest first within each group. */
export function listInvariants(db: Database.Database, taskId: string): Array<InvariantRow & { superseded: boolean }> {
  const rows = db.prepare(
    `SELECT i.*, EXISTS (SELECT 1 FROM sentinel_invariants s WHERE s.supersedes = i.invariant_id) AS superseded FROM sentinel_invariants i WHERE i.task_id = ?
     ORDER BY superseded ASC, i.approved_at DESC, i.rowid DESC LIMIT 500`
  ).all(taskId) as Array<InvariantRow & { superseded: number }>;
  return rows.map((r) => ({ ...r, superseded: r.superseded === 1 }));
}

const TEMPLATES: Readonly<Record<InvariantKind, ReadonlyArray<{ name: string; style: CandidateTest["style"]; spec: string }>>> = {
  idempotency: [
    { name: "repeat-yields-same-state", style: "property", spec: "For generated valid inputs, applying the operation twice leaves the same observable state and result as applying it once." },
    { name: "duplicate-request-key", style: "example", spec: "Submitting the same request (same idempotency key) twice creates exactly one effect; the second call returns the first result." },
    { name: "concurrent-duplicates", style: "property", spec: "Two concurrent submissions of the same request produce one effect, never two." }
  ],
  ledger_balance: [
    { name: "sum-preserved", style: "property", spec: "For any generated sequence of transfers, the sum of all balances before equals the sum after (no value created or destroyed)." },
    { name: "rejected-transfer-no-change", style: "negative", spec: "A transfer that is refused (insufficient funds, invalid account) leaves every balance unchanged." },
    { name: "partial-failure-rollback", style: "example", spec: "A failure between debit and credit leaves both sides as they were before the transfer." }
  ],
  monotonic_state: [
    { name: "never-moves-backwards", style: "property", spec: "For any generated sequence of events, the tracked state never moves to an earlier position in its order." },
    { name: "reordered-events", style: "property", spec: "Delivering the same events out of order never lowers the state reached." },
    { name: "illegal-regression-refused", style: "negative", spec: "An explicit request to move the state backwards is refused and leaves the state unchanged." }
  ],
  acl_denial: [
    { name: "unauthorized-denied", style: "negative", spec: "A principal without the required permission is denied, and the protected resource is unchanged and not disclosed." },
    { name: "role-matrix", style: "property", spec: "For every generated (principal role, action) pair outside the allowed matrix, the action is denied." },
    { name: "revoked-access", style: "example", spec: "After a permission is revoked, the next request by that principal is denied." }
  ],
  custom: [
    { name: "statement-holds", style: "property", spec: "For generated valid inputs, the approved statement holds after the operation." },
    { name: "statement-boundary", style: "example", spec: "At the boundary values named or implied by the statement, the statement still holds." },
    { name: "statement-violation-detected", style: "negative", spec: "A deliberately violating input is detected or refused rather than silently accepted." }
  ]
};

/**
 * Plain-text candidate test specifications derived from an approved invariant (a pure function: it reads the invariant and returns new objects). Each candidate carries the statement hash it was
 * derived from; a statement that no longer matches its stored hash is refused rather than used.
 */
export function candidateTestsFor(invariant: Readonly<Pick<InvariantRow, "invariant_id" | "kind" | "statement" | "statement_sha256">>): CandidateTest[] {
  if (sha(invariant.statement) !== invariant.statement_sha256) {
    throw new EngbrainError("POLICY_REFUSED", "the invariant statement does not match its approved hash");
  }
  const templates = TEMPLATES[invariant.kind];
  if (templates === undefined) {
    throw new EngbrainError("POLICY_REFUSED", `unknown invariant kind ${String(invariant.kind)}`);
  }
  return templates.map((t) => ({
    name: `${invariant.kind}:${t.name}`, invariantId: invariant.invariant_id, statementSha256: invariant.statement_sha256, style: t.style,
    spec: `${t.spec} Invariant: "${invariant.statement}"`
  }));
}
