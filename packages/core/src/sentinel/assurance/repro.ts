import { randomUUID } from "node:crypto";
import type Database from "better-sqlite3";
import { EngbrainError } from "../../errors.js";
import type { Actor } from "../../memory/operators.js";
import { addMemory, findSecretIn, parseNewMemory, type MemoryRow } from "../../memory/records.js";
import { getTask } from "../tasks.js";

/**
 * Reproductions (Sentinel 3D): what is needed to replay a failure found by a property test, fuzzer or race explorer — the seed, the minimized (shrunk) input, the artifacts and the tool. A
 * reproduction may be proposed as a memory CANDIDATE (approval stays a separate human act) and is linked to at most one candidate.
 */
export interface ReproInput {
  importId: string;
  hypId?: string;
  seed: string | null;
  minimizedInput: string | null;
  shrinkSteps: number | null;
  artifactHashes: string[];
  tool: { name: string; version?: string | null };
  replayHint: string | null;
  defectRef?: string;
}

const optLine = (v: string | null | undefined, max: number, what: string): string | null => {
  if (v === null || v === undefined) {
    return null;
  }
  if (typeof v !== "string" || v.length > max || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\p{Cf}\p{Zl}\p{Zp}]/u.test(v)) {
    throw new EngbrainError("POLICY_REFUSED", `${what} must be at most ${max} characters without control or invisible formatting characters`);
  }
  return v;
};

export function recordRepro(db: Database.Database, taskId: string, input: ReproInput, now?: Date): string {
  const seed = optLine(input.seed, 200, "seed");
  const minimized = optLine(input.minimizedInput, 4000, "minimized input");
  const replayHint = optLine(input.replayHint, 500, "replay hint");
  const defectRef = optLine(input.defectRef, 200, "defect reference");
  const toolName = optLine(input.tool?.name, 100, "tool name");
  if (toolName === null || toolName.trim() === "") {
    throw new EngbrainError("POLICY_REFUSED", "a reproduction must name the tool that found it");
  }
  if (input.shrinkSteps !== null && (!Number.isInteger(input.shrinkSteps) || input.shrinkSteps < 0)) {
    throw new EngbrainError("POLICY_REFUSED", "shrinkSteps is a non-negative integer (or null when the tool does not shrink)");
  }
  if (!Array.isArray(input.artifactHashes) || input.artifactHashes.length > 20 || !input.artifactHashes.every((h) => typeof h === "string" && /^[0-9a-f]{64}$/.test(h))) {
    throw new EngbrainError("POLICY_REFUSED", "artifactHashes is a list of at most 20 sha256 digests");
  }
  if (seed === null && minimized === null) {
    throw new EngbrainError("POLICY_REFUSED", "a reproduction needs a seed or a minimized input: without either it cannot be replayed");
  }
  if (findSecretIn({ seed, minimized, replayHint, defectRef }) !== null) {
    throw new EngbrainError("POLICY_REFUSED", "the reproduction looks like it contains a secret");
  }
  return db.transaction((): string => {
    getTask(db, taskId);
    if (db.prepare("SELECT 1 FROM evidence_imports WHERE import_id = ?").get(input.importId) === undefined) {
      throw new EngbrainError("INVALID_ROOT", "no such evidence import");
    }
    if (input.hypId !== undefined && db.prepare("SELECT 1 FROM sentinel_hypotheses WHERE hyp_id = ? AND task_id = ?").get(input.hypId, taskId) === undefined) {
      throw new EngbrainError("POLICY_REFUSED", "that hypothesis does not belong to this task");
    }
    const id = `rp_${randomUUID().replace(/-/g, "").slice(0, 16)}`;
    db.prepare("INSERT INTO sentinel_repro (repro_id, task_id, hyp_id, import_id, seed, minimized_input, shrink_steps, artifact_hashes_json, tool_json, replay_hint, defect_ref, memory_candidate_id, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)")
      .run(id, taskId, input.hypId ?? null, input.importId, seed, minimized, input.shrinkSteps, JSON.stringify([...new Set(input.artifactHashes)]), JSON.stringify({ name: toolName, version: input.tool.version ?? null }), replayHint, defectRef, (now ?? new Date()).toISOString());
    return id;
  }).immediate();
}

interface ReproRow { repro_id: string; task_id: string; import_id: string; seed: string | null; minimized_input: string | null; shrink_steps: number | null; tool_json: string; replay_hint: string | null; memory_candidate_id: string | null }

/**
 * Proposes a reproduction as a memory record. It is created through the normal memory API, so it lands as a CANDIDATE like every proposal (an approver still has to approve it), and the
 * reproduction is linked to it exactly once.
 */
export function proposeMemoryCandidate(db: Database.Database, reproId: string, actor: Actor, now?: Date): MemoryRow {
  return db.transaction((): MemoryRow => {
    const repro = db.prepare("SELECT * FROM sentinel_repro WHERE repro_id = ?").get(reproId) as ReproRow | undefined;
    if (repro === undefined) {
      throw new EngbrainError("INVALID_ROOT", "no such reproduction");
    }
    if (repro.memory_candidate_id !== null) {
      throw new EngbrainError("POLICY_REFUSED", `this reproduction was already proposed as ${repro.memory_candidate_id}`);
    }
    const artifact = db.prepare("SELECT artifact_name AS name, artifact_sha256 AS sha FROM evidence_imports WHERE import_id = ?").get(repro.import_id) as { name: string; sha: string };
    const tool = JSON.parse(repro.tool_json) as { name: string; version: string | null };
    const body = [
      `Reproduction ${repro.repro_id} of task ${repro.task_id}, found by ${tool.name}${tool.version === null ? "" : ` ${tool.version}`} (evidence import ${repro.import_id}).`,
      repro.seed === null ? null : `Seed: ${repro.seed}`,
      repro.shrink_steps === null ? null : `Shrink steps: ${repro.shrink_steps}`,
      repro.minimized_input === null ? null : `Minimized input: ${repro.minimized_input.slice(0, 1000)}`,
      repro.replay_hint === null ? null : `Replay: ${repro.replay_hint}`
    ].filter((l): l is string => l !== null).join("\n");
    const record = parseNewMemory({
      kind: "finding", title: `Reproducible failure found by ${tool.name}`.slice(0, 160), body, origin: "import", originDetail: `sentinel repro ${repro.repro_id}`,
      evidence: { type: "ci", method: `${tool.name} reproduction`.slice(0, 160), pointers: [{ kind: "artifact", name: artifact.name, sha256: artifact.sha }], artifacts: [{ name: artifact.name, sha256: artifact.sha }] }
    });
    const row = addMemory(db, record, { actor, ...(now === undefined ? {} : { now: () => now }) });
    db.prepare("UPDATE sentinel_repro SET memory_candidate_id = ? WHERE repro_id = ? AND memory_candidate_id IS NULL").run(row.record_id, reproId);
    return row;
  }).immediate();
}
