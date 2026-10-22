import type Database from "better-sqlite3";
import { EngbrainError } from "../errors.js";
import { requireRole, type Actor } from "../memory/operators.js";
import { verifyCapability } from "./capabilities.js";
import { assertCanApprove, getTask, systemBlock, type Who } from "./tasks.js";

/**
 * Bounded repair. A person starts a repair loop with a fixed (and capped) budget of iterations, time, tokens and cost; every repair iteration is counted (idempotently: a resumed controller replaying
 * the same key is not charged twice); retries back off exponentially and an iteration before the backoff elapsed is refused; time is measured by the controller's clock, not only by what the caller
 * reports; and the SAME failure recurring (or more distinct failures than iterations allowed) escalates to a person instead of looping. Exhausting any bound BLOCKS the task: there is no "fix until green".
 */
export interface RepairBudget { maxIterations: number; maxMs: number; maxTokens: number; maxCostMicro: number; maxSameFailure: number }
export const DEFAULT_REPAIR_BUDGET: RepairBudget = { maxIterations: 3, maxMs: 1_800_000, maxTokens: 200_000, maxCostMicro: 5_000_000, maxSameFailure: 2 };
/** Hard ceilings: no caller-chosen budget can exceed these. */
export const REPAIR_BUDGET_CAPS: RepairBudget = { maxIterations: 20, maxMs: 8 * 3_600_000, maxTokens: 10_000_000, maxCostMicro: 100_000_000, maxSameFailure: 10 };

export interface RepairState { iterations: number; tokens: number; costMicro: number; elapsedMs: number; budget: RepairBudget }
export interface IterationResult { allowed: boolean; reason: string | null; backoffMs: number; state: RepairState }

const REPAIRABLE_STATES: readonly string[] = ["IMPLEMENTING", "IMPLEMENTED", "VERIFYING", "FINDINGS_REPORTED", "REPAIRING", "REVERIFYING"];
const ITERATION_ROLES = ["builder", "assurance_controller"] as const;

const backoff = (n: number): number => Math.min(60_000, 1000 * 2 ** Math.max(0, n - 1));

function validBudget(budget: Partial<RepairBudget>): RepairBudget {
  const merged: RepairBudget = { ...DEFAULT_REPAIR_BUDGET, ...budget };
  for (const k of Object.keys(DEFAULT_REPAIR_BUDGET) as Array<keyof RepairBudget>) {
    const v = merged[k];
    if (!Number.isInteger(v) || v < 1) {
      throw new EngbrainError("POLICY_REFUSED", `repair budget ${k} must be a positive integer`);
    }
    if (v > REPAIR_BUDGET_CAPS[k]) {
      throw new EngbrainError("POLICY_REFUSED", `repair budget ${k} may be at most ${REPAIR_BUDGET_CAPS[k]}`);
    }
  }
  return merged;
}

/** Only an authenticated operator with the approve role (who did not build or check the task) starts a repair loop, and only for a live task that is being built, verified or repaired. */
export function startRepair(db: Database.Database, id: string, actor: Actor, budget: Partial<RepairBudget> = {}, now?: Date): RepairState {
  requireRole(actor, "approve");
  const merged = validBudget(budget);
  return db.transaction((): RepairState => {
    const task = getTask(db, id);
    if (!REPAIRABLE_STATES.includes(task.state)) {
      throw new EngbrainError("POLICY_REFUSED", `a ${task.state} task cannot start a repair loop`);
    }
    assertCanApprove(db, task, actor.id);
    db.prepare("INSERT OR IGNORE INTO sentinel_repair (task_id, budget_json, started_at) VALUES (?, ?, ?)").run(id, JSON.stringify(merged), (now ?? new Date()).toISOString());
    return readState(db, id);
  }).immediate();
}

interface RepairRow { budget_json: string; iterations: number; tokens: number; cost_micro: number; elapsed_ms: number; started_at: string; next_allowed_at: string; signatures_json: string }

function readRow(db: Database.Database, id: string): RepairRow {
  const r = db.prepare("SELECT * FROM sentinel_repair WHERE task_id = ?").get(id) as RepairRow | undefined;
  if (r === undefined || r.started_at === "") {
    throw new EngbrainError("POLICY_REFUSED", "no repair loop was started for this task");
  }
  return r;
}

function readState(db: Database.Database, id: string): RepairState {
  const r = readRow(db, id);
  return { iterations: r.iterations, tokens: r.tokens, costMicro: r.cost_micro, elapsedMs: r.elapsed_ms, budget: JSON.parse(r.budget_json) as RepairBudget };
}

/** Who may charge an iteration: the task's builder or assurance controller (live capability for THIS task), or an operator with the approve role. */
function assertMayIterate(db: Database.Database, storeDir: string, id: string, who: Who, now: Date): void {
  if ("operator" in who) {
    requireRole(who.operator, "approve");
    return;
  }
  const payload = verifyCapability(storeDir, who.capability, { now, taskId: id, roles: ITERATION_ROLES });
  if (getTask(db, id).cap_epoch !== payload.epoch) {
    throw new EngbrainError("POLICY_REFUSED", "the capability was revoked");
  }
}

function exhaustion(state: RepairState, sameCount: number, distinct: number): string | null {
  const b = state.budget;
  return state.iterations > b.maxIterations ? `the repair iteration limit (${b.maxIterations}) was exceeded`
    : distinct > b.maxIterations ? `${distinct} distinct failures exceed the repair iteration limit (${b.maxIterations}): escalating to a person`
      : state.elapsedMs > b.maxMs ? "the repair time budget was exhausted"
        : state.tokens > b.maxTokens ? "the token budget was exhausted"
          : state.costMicro > b.maxCostMicro ? "the cost budget was exhausted"
            : sameCount > b.maxSameFailure ? `the same failure recurred ${sameCount} times: escalating to a person`
              : null;
}

/** Charges one repair iteration. `iterationKey` makes it idempotent across a crash and resume. A cancelled, finished or blocked task is refused: revocation really stops future work. */
export function recordIteration(db: Database.Database, storeDir: string, id: string, who: Who, input: { iterationKey: string; tokens: number; costMicro: number; elapsedMs: number; failureSignature: string }, now?: Date): IterationResult {
  if (!/^[a-zA-Z0-9._:-]{1,80}$/.test(input.iterationKey) || ![input.tokens, input.costMicro, input.elapsedMs].every((n) => Number.isInteger(n) && n >= 0)) {
    throw new EngbrainError("POLICY_REFUSED", "an iteration needs a key and non-negative integer usage");
  }
  const signature = typeof input.failureSignature === "string" ? input.failureSignature.trim() : "";
  if (signature.length < 1 || signature.length > 200) {
    throw new EngbrainError("POLICY_REFUSED", "an iteration needs a failure signature (1-200 characters)");
  }
  const at = now ?? new Date();
  assertMayIterate(db, storeDir, id, who, at);
  return db.transaction((): IterationResult => {
    const task = getTask(db, id);
    if (["FAILED", "CANCELLED", "BLOCKED"].includes(task.state)) {
      throw new EngbrainError("POLICY_REFUSED", `the task is ${task.state}: no further repair is permitted`);
    }
    const row = readRow(db, id);
    if (db.prepare("SELECT 1 FROM sentinel_repair_keys WHERE task_id = ? AND iteration_key = ?").get(id, input.iterationKey) !== undefined) {
      return { allowed: true, reason: null, backoffMs: 0, state: readState(db, id) }; // a replay of an already-counted iteration
    }
    if (row.next_allowed_at !== "" && at.getTime() < new Date(row.next_allowed_at).getTime()) {
      throw new EngbrainError("POLICY_REFUSED", `backing off: the next repair iteration is allowed at ${row.next_allowed_at}`);
    }
    db.prepare("INSERT INTO sentinel_repair_keys (task_id, iteration_key) VALUES (?, ?)").run(id, input.iterationKey);
    const signatures = JSON.parse(row.signatures_json) as Record<string, number>;
    signatures[signature] = (signatures[signature] ?? 0) + 1;
    const wallClock = Math.max(0, at.getTime() - new Date(row.started_at).getTime());
    const elapsed = Math.max(row.elapsed_ms + input.elapsedMs, wallClock);
    const iterations = row.iterations + 1;
    const wait = backoff(iterations);
    db.prepare("UPDATE sentinel_repair SET iterations = ?, tokens = tokens + ?, cost_micro = cost_micro + ?, elapsed_ms = ?, signatures_json = ?, next_allowed_at = ? WHERE task_id = ?")
      .run(iterations, input.tokens, input.costMicro, elapsed, JSON.stringify(signatures), new Date(at.getTime() + wait).toISOString(), id);
    const state = readState(db, id);
    const reason = exhaustion(state, signatures[signature] ?? 0, Object.keys(signatures).length);
    if (reason !== null) {
      systemBlock(db, storeDir, id, reason, at);
      return { allowed: false, reason, backoffMs: 0, state };
    }
    return { allowed: true, reason: null, backoffMs: wait, state };
  }).immediate();
}
