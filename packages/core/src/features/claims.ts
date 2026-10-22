import { createHash } from "node:crypto";
import type Database from "better-sqlite3";
import { EngbrainError } from "../errors.js";
import { currentGenerationId } from "../store/generations.js";

/**
 * Candidate statements about features (typically from an optional, user-approved LOCAL model analysis, or typed by a person). They are LABELLED inferred/proposed and
 * stay `candidate` until a human approves them with source evidence that exists in the current generation. Nothing here calls a model or the network.
 * Repetition changes nothing: a claim is identified by the hash of its normalised statement TOGETHER WITH its evidence references, so resubmitting it (a hundred times,
 * from any source) neither adds a row nor strengthens it, while the same statement with different evidence is a separate claim (a bogus proposal cannot squat it). Evidence is versioned by a fingerprint of the evidence content, so a claim goes `stale` when what it points at changes or disappears.
 */
export const CLAIM_LIMITS = { statement: 500, evidence: 20, evidenceRef: 300, batch: 200 } as const;

export interface Proposal { statement: string; evidence?: string[] }
export interface ClaimRecord {
  id: number;
  statement: string;
  source: "model" | "human";
  sourceDetail: string | null;
  trust: "candidate" | "approved" | "retired";
  evidence: string[];
  createdAt: string;
  approvedBy: string | null;
  approvedAt: string | null;
  retiredAt: string | null;
  retiredReason: string | null;
  /** Current standing of the evidence: `ok`, `evidence_missing` or `evidence_changed` (the claim must be re-validated), `no_evidence`. */
  evidenceStatus: "ok" | "evidence_missing" | "evidence_changed" | "no_evidence";
  label: string;
}

const normalise = (s: string): string => s.normalize("NFC").toLowerCase().replace(/\s+/g, " ").trim();
const hashOf = (s: string): string => createHash("sha256").update(normalise(s)).digest("hex");
/** Control, format (zero-width, bidirectional, tag) and separator characters are refused in anything a person or a terminal will read. */
const UNSAFE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;
const REF_SHAPE = /^(?:[a-z_]+:[0-9a-f]{16}|file:[^\0]+|sym:[^\0]+#[^\0]+)$/;

/** The content hash an evidence reference currently stands for in the published generation, or null when it does not exist there. */
function evidenceHash(db: Database.Database, generationId: number, ref: string): string | null {
  if (ref.startsWith("file:")) {
    return (db.prepare("SELECT content_hash AS h FROM generation_files WHERE generation_id = ? AND path = ? AND content_hash IS NOT NULL").get(generationId, ref.slice(5)) as { h: string } | undefined)?.h ?? null;
  }
  if (ref.startsWith("sym:")) {
    const at = ref.lastIndexOf("#");
    return (db.prepare("SELECT content_hash AS h FROM symbol_occurrences WHERE generation_id = ? AND path = ? AND qualified_name = ? AND kind != 'module' LIMIT 1").get(generationId, ref.slice(4, at), ref.slice(at + 1)) as { h: string } | undefined)?.h ?? null;
  }
  const row = db.prepare("SELECT content_hash AS h, kind FROM feature_entities WHERE generation_id = ? AND entity_id = ?").get(generationId, ref) as { h: string | null; kind: string } | undefined;
  return row === undefined ? null : row.h ?? `entity:${ref}`;
}

const fingerprintOf = (hashes: readonly string[]): string => createHash("sha256").update([...hashes].sort().join("\n")).digest("hex");

function recordOf(db: Database.Database, row: Record<string, unknown>, generationId: number | null): ClaimRecord {
  const evidence = JSON.parse(row["evidence_json"] as string) as string[];
  let evidenceStatus: ClaimRecord["evidenceStatus"] = evidence.length === 0 ? "no_evidence" : "ok";
  if (generationId !== null && evidence.length > 0) {
    const hashes = evidence.map((ref) => evidenceHash(db, generationId, ref));
    if (hashes.some((h) => h === null)) {
      evidenceStatus = "evidence_missing";
    } else if (fingerprintOf(hashes as string[]) !== row["scope_fingerprint"]) {
      evidenceStatus = "evidence_changed";
    }
  }
  const trust = row["trust"] as ClaimRecord["trust"];
  return {
    id: row["id"] as number, statement: row["statement"] as string, source: row["source"] as ClaimRecord["source"], sourceDetail: row["source_detail"] as string | null, trust, evidence,
    createdAt: row["created_at"] as string, approvedBy: row["approved_by"] as string | null, approvedAt: row["approved_at"] as string | null, retiredAt: row["retired_at"] as string | null,
    retiredReason: row["retired_reason"] as string | null, evidenceStatus,
    label: trust === "candidate" ? (row["source"] === "model" ? "INFERRED / PROPOSED by a model: not verified" : "PROPOSED by a person: not yet approved") : trust === "approved" ? "APPROVED by a person against source evidence (re-check if evidenceStatus is not ok)" : "RETIRED"
  };
}

export interface SubmitResult { inserted: number; duplicates: number; rejected: Array<{ index: number; reason: string }> }

/**
 * Records proposals as `candidate`. A proposal can carry ONLY a statement and evidence references: any attempt to set trust, approval or other fields is rejected.
 * Evidence references (entity id, `file:path`, `sym:path#qualified`) that do not exist in the current generation are rejected.
 */
export function submitCandidates(db: Database.Database, proposals: readonly unknown[], options: { source: "model" | "human"; sourceDetail?: string; now?: () => Date }): SubmitResult {
  const result: SubmitResult = { inserted: 0, duplicates: 0, rejected: [] };
  const now = (options.now ?? (() => new Date()))().toISOString();
  if (options.sourceDetail !== undefined && (options.sourceDetail.length > 120 || UNSAFE.test(options.sourceDetail))) {
    throw new EngbrainError("POLICY_REFUSED", "sourceDetail must be at most 120 characters without control or invisible formatting characters");
  }
  if (proposals.length > CLAIM_LIMITS.batch) {
    throw new EngbrainError("POLICY_REFUSED", `at most ${CLAIM_LIMITS.batch} proposals per submission`);
  }
  db.transaction(() => {
    const generationId = currentGenerationId(db);
    proposals.forEach((raw, index) => {
      const reject = (reason: string): void => void result.rejected.push({ index, reason });
      if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
        return reject("a proposal must be an object");
      }
      const p = raw as Record<string, unknown>;
      const extra = Object.keys(p).find((k) => k !== "statement" && k !== "evidence");
      if (extra !== undefined) {
        return reject(`a proposal cannot set "${extra.slice(0, 30)}": proposals carry only a statement and evidence, and are always candidates`);
      }
      if (typeof p["statement"] !== "string" || p["statement"].trim().length < 3 || p["statement"].length > CLAIM_LIMITS.statement || UNSAFE.test(p["statement"])) {
        return reject(`statement must be 3-${CLAIM_LIMITS.statement} characters without control or invisible formatting characters`);
      }
      const evidence = p["evidence"] ?? [];
      if (!Array.isArray(evidence) || evidence.length > CLAIM_LIMITS.evidence || evidence.some((e) => typeof e !== "string" || e.length > CLAIM_LIMITS.evidenceRef || !REF_SHAPE.test(e))) {
        return reject("evidence must be a list of entity ids, file: or sym: references");
      }
      const hashes: string[] = [];
      for (const ref of evidence as string[]) {
        const h = generationId === null ? null : evidenceHash(db, generationId, ref);
        if (h === null) {
          return reject("an evidence reference does not exist in the current generation");
        }
        hashes.push(h);
      }
      const statement = p["statement"].trim();
      const statementHash = hashOf(statement);
      const identity = createHash("sha256").update(`${statementHash}\0${[...new Set(evidence as string[])].sort().join("\0")}`).digest("hex");
      const inserted = db.prepare(
        `INSERT OR IGNORE INTO feature_claims (statement_hash, identity_hash, statement, source, source_detail, trust, evidence_json, scope_fingerprint, created_at) VALUES (?, ?, ?, ?, ?, 'candidate', ?, ?, ?)`
      ).run(statementHash, identity, statement, options.source, options.sourceDetail ?? null, JSON.stringify(evidence), hashes.length === 0 ? null : fingerprintOf(hashes), now);
      if (inserted.changes === 0) {
        result.duplicates += 1; // repetition is inert: same row, same trust, nothing strengthened
      } else {
        result.inserted += 1;
      }
    });
  }).immediate();
  return result;
}

/**
 * A person approves a candidate. Requires evidence that resolves NOW and is unchanged since the proposal; the approver must differ from the proposing model's recorded name.
 * LIMIT: identity is ASSERTED, not authenticated: a local process that can run this command can claim any name. The controls are procedural (an explicit act with `--by` and `--yes`,
 * evidence required, no automatic path, no model call in engbrain), not a guarantee against a hostile local agent.
 */
export function approveClaim(db: Database.Database, id: number, options: { approvedBy: string; now?: () => Date }): ClaimRecord {
  const by = options.approvedBy.trim();
  if (by.length < 1 || by.length > 80 || UNSAFE.test(by)) {
    throw new EngbrainError("INVALID_ROOT", "approvedBy is required (1-80 characters, no control or invisible formatting characters)");
  }
  return db.transaction((): ClaimRecord => {
    const row = db.prepare("SELECT * FROM feature_claims WHERE id = ?").get(id) as Record<string, unknown> | undefined;
    if (row === undefined) {
      throw new EngbrainError("INVALID_ROOT", "no such claim");
    }
    if (row["trust"] !== "candidate") {
      throw new EngbrainError("POLICY_REFUSED", `only a candidate can be approved (this one is ${String(row["trust"])})`);
    }
    if (row["source"] === "model" && normalise(by) === normalise(String(row["source_detail"] ?? ""))) {
      throw new EngbrainError("POLICY_REFUSED", "a model cannot approve its own proposal: approval must come from a person");
    }
    const generationId = currentGenerationId(db);
    const evidence = JSON.parse(row["evidence_json"] as string) as string[];
    if (evidence.length === 0) {
      throw new EngbrainError("POLICY_REFUSED", "a claim without source evidence cannot be approved");
    }
    const hashes = evidence.map((ref) => (generationId === null ? null : evidenceHash(db, generationId, ref)));
    if (hashes.some((h) => h === null)) {
      throw new EngbrainError("POLICY_REFUSED", "evidence for this claim no longer exists in the current generation: re-validate it first");
    }
    // approval binds to the evidence a person reviewed: if it changed since the claim was proposed, approval is refused (no silent re-binding to newer evidence)
    if (fingerprintOf(hashes as string[]) !== row["scope_fingerprint"]) {
      throw new EngbrainError("POLICY_REFUSED", "the evidence changed since this claim was proposed: review the current evidence and run `feature rebind` before approving");
    }
    db.prepare("UPDATE feature_claims SET trust = 'approved', approved_by = ?, approved_at = ? WHERE id = ?").run(by, (options.now ?? (() => new Date()))().toISOString(), id);
    return recordOf(db, db.prepare("SELECT * FROM feature_claims WHERE id = ?").get(id) as Record<string, unknown>, generationId);
  }).immediate();
}

/** Re-binds a CANDIDATE to the evidence as it is now (an explicit act after reviewing it). Approved claims are never re-bound: retire and propose again. */
export function rebindClaim(db: Database.Database, id: number): ClaimRecord {
  return db.transaction((): ClaimRecord => {
    const row = db.prepare("SELECT * FROM feature_claims WHERE id = ?").get(id) as Record<string, unknown> | undefined;
    if (row === undefined) {
      throw new EngbrainError("INVALID_ROOT", "no such claim");
    }
    if (row["trust"] !== "candidate") {
      throw new EngbrainError("POLICY_REFUSED", "only a candidate can be re-bound to current evidence");
    }
    const generationId = currentGenerationId(db);
    const evidence = JSON.parse(row["evidence_json"] as string) as string[];
    const hashes = evidence.map((ref) => (generationId === null ? null : evidenceHash(db, generationId, ref)));
    if (evidence.length === 0 || hashes.some((h) => h === null)) {
      throw new EngbrainError("POLICY_REFUSED", "the evidence no longer exists in the current generation");
    }
    db.prepare("UPDATE feature_claims SET scope_fingerprint = ? WHERE id = ?").run(fingerprintOf(hashes as string[]), id);
    return recordOf(db, db.prepare("SELECT * FROM feature_claims WHERE id = ?").get(id) as Record<string, unknown>, generationId);
  }).immediate();
}

export function retireClaim(db: Database.Database, id: number, options: { reason: string; now?: () => Date }): ClaimRecord {
  return db.transaction((): ClaimRecord => {
    const row = db.prepare("SELECT * FROM feature_claims WHERE id = ?").get(id) as Record<string, unknown> | undefined;
    if (row === undefined) {
      throw new EngbrainError("INVALID_ROOT", "no such claim");
    }
    if (row["trust"] === "retired") {
      throw new EngbrainError("POLICY_REFUSED", "already retired");
    }
    db.prepare("UPDATE feature_claims SET trust = 'retired', retired_at = ?, retired_reason = ? WHERE id = ?").run((options.now ?? (() => new Date()))().toISOString(), options.reason.slice(0, 300), id);
    return recordOf(db, db.prepare("SELECT * FROM feature_claims WHERE id = ?").get(id) as Record<string, unknown>, currentGenerationId(db));
  }).immediate();
}

export function listClaims(db: Database.Database, options: { trust?: ClaimRecord["trust"]; limit?: number } = {}): ClaimRecord[] {
  const limit = Math.min(Math.max(1, Math.floor(options.limit ?? 100)), 500);
  return db.transaction((): ClaimRecord[] => {
    const generationId = currentGenerationId(db);
    const rows = (options.trust === undefined
      ? db.prepare("SELECT * FROM feature_claims ORDER BY id LIMIT ?").all(limit)
      : db.prepare("SELECT * FROM feature_claims WHERE trust = ? ORDER BY id LIMIT ?").all(options.trust, limit)) as Array<Record<string, unknown>>;
    return rows.map((row) => recordOf(db, row, generationId));
  })();
}
