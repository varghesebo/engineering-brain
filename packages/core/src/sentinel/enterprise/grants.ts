import { randomUUID } from "node:crypto";
import type Database from "better-sqlite3";
import { EngbrainError } from "../../errors.js";
import { requireRole, type Actor } from "../../memory/operators.js";
import { assertCanApprove, type TaskRow } from "../tasks.js";

/**
 * Per-principal, per-repository-scope grants (Sentinel 3E). A grant is given by an admin who is not the grantee, covers either the whole repository (`*`) or a repository-relative path prefix,
 * and can only be revoked, once (schema triggers refuse any other change and any delete). Grants are checked at the moment of use: a revoked grant stops counting immediately, including for
 * approvals and exceptions recorded earlier.
 */
export const GRANT_ROLES = ["approver", "second_approver", "exception_approver", "auditor", "exporter"] as const;
export type GrantRole = (typeof GRANT_ROLES)[number];
export interface GrantRow { grant_id: string; principal: string; role: GrantRole; repo_scope: string; granted_by: string; at: string; revoked_at: string | null }

const PRINCIPAL = /^[a-zA-Z0-9._:-]{1,60}$/;
const clock = (now?: Date): Date => now ?? new Date();

function safeRepoScope(scope: string): string {
  const t = scope.trim();
  if (t === "*") {
    return t;
  }
  if (t.length < 1 || t.length > 500 || /[\p{Cc}\p{Cf}]/u.test(t) || t.startsWith("/") || t.includes("\\") || t.split("/").some((s, i, all) => s === ".." || (s === "" && i !== all.length - 1))) {
    throw new EngbrainError("POLICY_REFUSED", "a grant scope is `*` or a repository-relative path prefix");
  }
  return t;
}

/** True when the grant's scope contains every path of the task's scope. */
export function grantCovers(grantScope: string, taskScope: readonly string[]): boolean {
  if (grantScope === "*") {
    return true;
  }
  const prefix = grantScope.endsWith("/") ? grantScope : `${grantScope}/`;
  return taskScope.length > 0 && taskScope.every((p) => p === grantScope || p.startsWith(prefix));
}

export function grant(db: Database.Database, actor: Actor, principal: string, role: GrantRole, repoScope: string, now?: Date): GrantRow {
  requireRole(actor, "admin");
  if (!PRINCIPAL.test(principal) || !GRANT_ROLES.includes(role)) {
    throw new EngbrainError("POLICY_REFUSED", `a grant names a simple principal and one of: ${GRANT_ROLES.join(", ")}`);
  }
  if (actor.id === principal) {
    throw new EngbrainError("POLICY_REFUSED", "nobody can grant a role to themselves");
  }
  const row: GrantRow = { grant_id: `gr_${randomUUID().replace(/-/g, "").slice(0, 16)}`, principal, role, repo_scope: safeRepoScope(repoScope), granted_by: actor.id, at: clock(now).toISOString(), revoked_at: null };
  db.prepare("INSERT INTO sentinel_principal_grants (grant_id, principal, role, repo_scope, granted_by, at, revoked_at) VALUES (@grant_id, @principal, @role, @repo_scope, @granted_by, @at, @revoked_at)").run(row);
  return row;
}

export function revokeGrant(db: Database.Database, actor: Actor, grantId: string, now?: Date): void {
  requireRole(actor, "admin");
  if (db.prepare("UPDATE sentinel_principal_grants SET revoked_at = ? WHERE grant_id = ? AND revoked_at IS NULL").run(clock(now).toISOString(), grantId).changes !== 1) {
    throw new EngbrainError("INVALID_ROOT", "no such active grant");
  }
}

/** The principal's grants of these roles that are in force now and cover the whole task scope. */
export function activeGrants(db: Database.Database, principal: string, roles: readonly GrantRole[], taskScope: readonly string[], now?: Date): GrantRow[] {
  const at = clock(now).toISOString();
  return (db.prepare("SELECT * FROM sentinel_principal_grants WHERE principal = ? AND revoked_at IS NULL AND at <= ? ORDER BY at").all(principal, at) as GrantRow[])
    .filter((g) => roles.includes(g.role) && grantCovers(g.repo_scope, taskScope));
}

export function assertGrant(db: Database.Database, principal: string, role: GrantRole | readonly GrantRole[], taskScope: readonly string[], now?: Date): GrantRow {
  const roles = typeof role === "string" ? [role] : role;
  const found = activeGrants(db, principal, roles, taskScope, now)[0];
  if (found === undefined) {
    throw new EngbrainError("POLICY_REFUSED", `${principal} holds no active ${roles.join("/")} grant covering this task's scope`);
  }
  return found;
}

/** An approval counts as independent only if the principal may approve at all (not the builder, never an agent role on the task) AND holds an approver grant for the task's scope. */
export function assertIndependentApproval(db: Database.Database, task: TaskRow, principal: string, now?: Date): GrantRow {
  assertCanApprove(db, task, principal);
  return assertGrant(db, principal, ["approver", "second_approver"], JSON.parse(task.scope_json) as string[], now);
}
