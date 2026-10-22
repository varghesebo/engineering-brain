import type Database from "better-sqlite3";
import { EngbrainError } from "../errors.js";
import { getTask, systemBlock } from "./tasks.js";

/**
 * Bounded repair. A task gets a fixed budget of iterations, time, tokens and cost; every repair iteration is counted (idempotently: a resumed controller replaying the same key is not charged twice);
 * retries back off exponentially; and the SAME failure recurring escalates to a person instead of looping. Exhausting any bound BLOCKS the task: there is no "fix until green".
 */
export interface RepairBudget { maxIterations: number; maxMs: number; maxTokens: number; maxCostMicro: number; maxSameFailure: number }
export const DEFAULT_REPAIR_BUDGET: RepairBudget = { maxIterations: 3, maxMs: 1_800_000, maxTokens: 200_000, maxCostMicro: 5_000_000, maxSameFailure: 2 };

export interface RepairState { iterations: number; tokens: number; costMicro: number; elapsedMs: number; budget: RepairBudget }
export interface IterationResult { allowed: boolean; reason: string | null; backoffMs: number; state: RepairState }

const backoff = (n: number): number => Math.min(60_000, 1000 * 2 ** Math.max(0, n - 1));

export function startRepair(db: Database.Database, id: string, budget: Partial<RepairBudget> = {}): RepairState {
  const merged = { ...DEFAULT_REPAIR_BUDGET, ...budget };
  for (const [k, v] of Object.entries(merged)) {
    if (!Number.isInteger(v) || v < 1) {
      throw new EngbrainError("POLICY_REFUSED", `repair budget ${k} must be a positive integer`);
    }
  }
  getTask(db, id);
  db.prepare("INSERT OR IGNORE INTO sentinel_repair (task_id, budget_json) VALUES (?, ?)").run(id, JSON.stringify(merged));
  return readState(db, id);
}

function readState(db: Database.Database, id: string): RepairState {
  const r = db.prepare("SELECT * FROM sentinel_repair WHERE task_id = ?").get(id) as { budget_json: string; iterations: number; tokens: number; cost_micro: number; elapsed_ms: number } | undefined;
  if (r === undefined) {
    throw new EngbrainError("POLICY_REFUSED", "no repair loop was started for this task");
  }
  return { iterations: r.iterations, tokens: r.tokens, costMicro: r.cost_micro, elapsedMs: r.elapsed_ms, budget: JSON.parse(r.budget_json) as RepairBudget };
}

/** Charges one repair iteration. `iterationKey` makes it idempotent across a crash and resume. A cancelled or finished task is refused: revocation really stops future work. */
export function recordIteration(db: Database.Database, storeDir: string, id: string, input: { iterationKey: string; tokens: number; costMicro: number; elapsedMs: number; failureSignature: string }, now?: Date): IterationResult {
  if (!/^[a-zA-Z0-9._:-]{1,80}$/.test(input.iterationKey) || ![input.tokens, input.costMicro, input.elapsedMs].every((n) => Number.isInteger(n) && n >= 0)) {
    throw new EngbrainError("POLICY_REFUSED", "an iteration needs a key and non-negative integer usage");
  }
  return db.transaction((): IterationResult => {
    const task = getTask(db, id);
    if (["FAILED", "CANCELLED", "BLOCKED"].includes(task.state)) {
      throw new EngbrainError("POLICY_REFUSED", `the task is ${task.state}: no further repair is permitted`);
    }
    const before = readState(db, id);
    if (db.prepare("INSERT OR IGNORE INTO sentinel_repair_keys (task_id, iteration_key) VALUES (?, ?)").run(id, input.iterationKey).changes === 0) {
      return { allowed: true, reason: null, backoffMs: 0, state: before }; // a replay of an already-counted iteration
    }
    const row = db.prepare("SELECT signatures_json AS s FROM sentinel_repair WHERE task_id = ?").get(id) as { s: string };
    const signatures = JSON.parse(row.s) as Record<string, number>;
    signatures[input.failureSignature] = (signatures[input.failureSignature] ?? 0) + 1;
    db.prepare("UPDATE sentinel_repair SET iterations = iterations + 1, tokens = tokens + ?, cost_micro = cost_micro + ?, elapsed_ms = elapsed_ms + ?, signatures_json = ? WHERE task_id = ?")
      .run(input.tokens, input.costMicro, input.elapsedMs, JSON.stringify(signatures), id);
    const state = readState(db, id);
    const b = state.budget;
    const reason = state.iterations > b.maxIterations ? `the repair iteration limit (${b.maxIterations}) was exceeded`
      : state.elapsedMs > b.maxMs ? "the repair time budget was exhausted"
        : state.tokens > b.maxTokens ? "the token budget was exhausted"
          : state.costMicro > b.maxCostMicro ? "the cost budget was exhausted"
            : (signatures[input.failureSignature] ?? 0) > b.maxSameFailure ? `the same failure recurred ${signatures[input.failureSignature]} times: escalating to a person`
              : null;
    if (reason !== null) {
      systemBlock(db, storeDir, id, reason, now);
      return { allowed: false, reason, backoffMs: 0, state };
    }
    return { allowed: true, reason: null, backoffMs: backoff(state.iterations), state };
  }).immediate();
}
