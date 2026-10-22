import { createHash, randomBytes } from "node:crypto";
import type Database from "better-sqlite3";
import { EngbrainError } from "../errors.js";
import { scanForSecrets } from "../secretScan.js";
import { currentGenerationId } from "../store/generations.js";
import { reachableFrom } from "../history/changes.js";
import { requireRole, type Actor } from "./operators.js";
import { needsSubstantiation } from "./evaluate.js";
import { prep } from "./prepared.js";

export const MEMORY_KINDS = ["observation", "claim", "decision", "finding", "bug", "fix", "test_evidence", "rejected_approach"] as const;
export type MemoryKind = (typeof MEMORY_KINDS)[number];
export type MemoryStatus = "candidate" | "approved" | "verified" | "stale" | "rejected";
export type MemoryOrigin = "human" | "model" | "ci" | "import";
export const LINK_RELS = ["fixes", "caused_by", "verifies", "supersedes", "related_to", "rejects", "substantiated_by"] as const;
export type LinkRel = (typeof LINK_RELS)[number];
export const EVIDENCE_TYPES = ["static_analysis", "test", "review", "incident", "ci", "manual", "model_inference"] as const;

export const MEMORY_LIMITS = { title: 160, body: 2000, claim: 500, pointers: 40, commits: 20, requirements: 20, artifacts: 20, predicates: 40, links: 20, observationDays: 90, reason: 300, envValue: 200 } as const;

/** Control, format (zero-width, bidirectional, tag), line and paragraph separator characters are refused in anything a person or a terminal will read (newlines and tabs are allowed in the body). */
// eslint-disable-next-line no-control-regex
const UNSAFE_LINE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;
const UNSAFE_BODY = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\p{Cf}\p{Zl}\p{Zp}]/u;
const ID = /^mem_[0-9a-f]{16}$/;
const OID = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;

export type PointerInput =
  | { kind: "file"; path: string }
  | { kind: "symbol"; path: string; qualifiedName: string }
  | { kind: "feature"; entity: string }
  | { kind: "test"; path: string; title?: string; failing?: boolean }
  | { kind: "commit"; oid: string; role: "introduced" | "fixed" | "verified" | "related" }
  | { kind: "requirement"; ref: string }
  | { kind: "incident"; ref: string }
  | { kind: "artifact"; name: string; sha256?: string };

export type Predicate =
  | { type: "source_hash"; pointer: number }
  | { type: "test_present"; pointer: number }
  | { type: "environment"; key: string; expect: string };

export interface NewMemory {
  kind: MemoryKind;
  title: string;
  body: string;
  validFrom?: string;
  validTo?: string;
  expiresAt?: string;
  origin: MemoryOrigin;
  originDetail?: string;
  scope?: { paths?: string[]; features?: string[]; symbols?: string[] };
  evidence: { claim?: string; pointers: PointerInput[]; type: (typeof EVIDENCE_TYPES)[number]; method?: string; environment?: Record<string, string>; artifacts?: Array<{ name: string; sha256?: string }> };
  invalidation?: Predicate[];
  links?: Array<{ rel: LinkRel; target: string }>;
  supersedes?: string;
}

export interface ResolvedPointer { kind: string; path: string | null; ref: string | null; contentHash: string | null; extra: Record<string, unknown> }

const isPlain = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const only = (o: Record<string, unknown>, allowed: readonly string[], what: string): void => {
  const extra = Object.keys(o).find((k) => !allowed.includes(k));
  if (extra !== undefined) {
    throw new EngbrainError("POLICY_REFUSED", `${what} does not accept ${JSON.stringify(extra.slice(0, 30)).replace(/[^\x20-\x7e]/g, "?")}`); // untrusted key: shown escaped and truncated
  }
};
const line = (v: unknown, max: number, what: string, min = 1): string => {
  if (typeof v !== "string" || v.length < min || v.length > max || UNSAFE_LINE.test(v)) {
    throw new EngbrainError("POLICY_REFUSED", `${what} must be ${min}-${max} characters without control or invisible formatting characters`);
  }
  return v;
};
/** A strict UTC timestamp: the calendar fields must survive a round trip (no 2026-02-31 silently becoming March, no 24:00 becoming tomorrow). */
export function parseIso(v: unknown, what: string): string {
  const m = typeof v === "string" ? /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$/.exec(v) : null;
  if (m === null) {
    throw new EngbrainError("POLICY_REFUSED", `${what} must be an ISO-8601 UTC timestamp like 2026-01-31T12:00:00Z`);
  }
  const d = new Date(v as string);
  const back = d.toISOString();
  if (Number.isNaN(d.getTime()) || back.slice(0, 10) !== `${m[1]}-${m[2]}-${m[3]}` || back.slice(11, 19) !== `${m[4]}:${m[5]}:${m[6]}`) {
    throw new EngbrainError("POLICY_REFUSED", `${what} is not a real calendar time`);
  }
  return back;
}
const iso = parseIso;
const noSecrets = (text: string, what: string): void => {
  if (scanForSecrets(text) !== null) {
    throw new EngbrainError("POLICY_REFUSED", `${what} looks like it contains a secret: memory never stores secrets`);
  }
};

/**
 * Every string anywhere inside a value, plus `key: value` and `key=value` lines for each object entry (the secret scanner recognises credential ASSIGNMENTS, which JSON hides behind a
 * quote). Used on EVERYTHING a record stores, at write and at export, not just the title and body.
 */
export function stringsOf(value: unknown, out: string[] = [], depth = 0): string[] {
  if (typeof value === "string") {
    out.push(value);
  } else if (Array.isArray(value) && depth < 6) {
    value.forEach((v) => stringsOf(v, out, depth + 1));
  } else if (typeof value === "object" && value !== null && depth < 6) {
    for (const [k, v] of Object.entries(value)) {
      out.push(k);
      if (typeof v === "string") {
        // the scanner's credential-assignment rule wants a quoted value right after a key that starts at a word boundary: `DB_PASSWORD` is tried as `DB-PASSWORD` too
        const dashed = k.replace(/_/g, "-");
        out.push(`${k}: ${v}`, `${k}=${v}`, `${k}="${v}"`, `${k}: "${v}"`, `${dashed}="${v}"`, `${dashed}: "${v}"`);
      }
      stringsOf(v, out, depth + 1);
    }
  }
  return out;
}
/** The first stored string that looks like a secret, or null. */
export const findSecretIn = (value: unknown): string | null => stringsOf(value).find((t) => scanForSecrets(t) !== null) ?? null;
const hashOf = (value: unknown): string => createHash("sha256").update(JSON.stringify(value)).digest("hex");

/** Strict, closed-schema validation of a memory proposal (untrusted input from a file or another process). */
export function parseNewMemory(raw: unknown): NewMemory {
  if (!isPlain(raw)) {
    throw new EngbrainError("POLICY_REFUSED", "a memory record must be an object");
  }
  only(raw, ["kind", "title", "body", "validFrom", "validTo", "expiresAt", "origin", "originDetail", "scope", "evidence", "invalidation", "links", "supersedes"], "a memory record");
  if (!MEMORY_KINDS.includes(raw["kind"] as MemoryKind)) {
    throw new EngbrainError("POLICY_REFUSED", `kind must be one of ${MEMORY_KINDS.join(", ")}`);
  }
  if (!["human", "model", "ci", "import"].includes(raw["origin"] as string)) {
    throw new EngbrainError("POLICY_REFUSED", "origin must be human, model, ci or import");
  }
  if (typeof raw["body"] !== "string" || raw["body"].length < 1 || raw["body"].length > MEMORY_LIMITS.body || UNSAFE_BODY.test(raw["body"])) {
    throw new EngbrainError("POLICY_REFUSED", `body must be 1-${MEMORY_LIMITS.body} characters without control or invisible formatting characters`);
  }
  const ev = raw["evidence"];
  if (!isPlain(ev) || !Array.isArray(ev["pointers"])) {
    throw new EngbrainError("POLICY_REFUSED", "evidence must be an object with a pointers array");
  }
  only(ev, ["claim", "pointers", "type", "method", "environment", "artifacts"], "evidence");
  if (!EVIDENCE_TYPES.includes(ev["type"] as (typeof EVIDENCE_TYPES)[number])) {
    throw new EngbrainError("POLICY_REFUSED", `evidence.type must be one of ${EVIDENCE_TYPES.join(", ")}`);
  }
  if (ev["pointers"].length > MEMORY_LIMITS.pointers) {
    throw new EngbrainError("POLICY_REFUSED", `at most ${MEMORY_LIMITS.pointers} evidence pointers`);
  }
  const pointers = (ev["pointers"] as unknown[]).map((p, i): PointerInput => {
    if (!isPlain(p)) {
      throw new EngbrainError("POLICY_REFUSED", `pointer ${i} must be an object`);
    }
    switch (p["kind"]) {
      case "file": only(p, ["kind", "path"], "a file pointer"); return { kind: "file", path: line(p["path"], 1024, "pointer path") };
      case "symbol": only(p, ["kind", "path", "qualifiedName"], "a symbol pointer"); return { kind: "symbol", path: line(p["path"], 1024, "pointer path"), qualifiedName: line(p["qualifiedName"], 300, "symbol name") };
      case "feature": only(p, ["kind", "entity"], "a feature pointer"); return { kind: "feature", entity: line(p["entity"], 400, "feature entity") };
      case "test": only(p, ["kind", "path", "title", "failing"], "a test pointer"); return { kind: "test", path: line(p["path"], 1024, "test path"), ...(p["title"] === undefined ? {} : { title: line(p["title"], 200, "test title") }), ...(p["failing"] === true ? { failing: true } : {}) };
      case "commit":
        only(p, ["kind", "oid", "role"], "a commit pointer");
        if (typeof p["oid"] !== "string" || !OID.test(p["oid"]) || !["introduced", "fixed", "verified", "related"].includes(p["role"] as string)) {
          throw new EngbrainError("POLICY_REFUSED", "a commit pointer needs a full commit id and a role (introduced, fixed, verified, related)");
        }
        return { kind: "commit", oid: p["oid"], role: p["role"] as "introduced" | "fixed" | "verified" | "related" };
      case "requirement": only(p, ["kind", "ref"], "a requirement pointer"); return { kind: "requirement", ref: line(p["ref"], 300, "requirement reference") };
      case "incident": only(p, ["kind", "ref"], "an incident pointer"); return { kind: "incident", ref: line(p["ref"], 300, "incident reference") };
      case "artifact": only(p, ["kind", "name", "sha256"], "an artifact pointer"); return { kind: "artifact", name: line(p["name"], 300, "artifact name"), ...(p["sha256"] === undefined ? {} : { sha256: /^[0-9a-f]{64}$/.test(String(p["sha256"])) ? String(p["sha256"]) : (() => { throw new EngbrainError("POLICY_REFUSED", "artifact sha256 must be 64 hex characters"); })() }) };
      default: throw new EngbrainError("POLICY_REFUSED", `pointer ${i} has an unknown kind`);
    }
  });
  const environment: Record<string, string> = {};
  if (ev["environment"] !== undefined) {
    if (!isPlain(ev["environment"]) || Object.keys(ev["environment"]).length > 20) {
      throw new EngbrainError("POLICY_REFUSED", "evidence.environment must be a small object of strings");
    }
    for (const [k, v] of Object.entries(ev["environment"])) {
      environment[line(k, 60, "environment key")] = line(v, MEMORY_LIMITS.envValue, "environment value");
    }
  }
  const artifacts = Array.isArray(ev["artifacts"]) ? (ev["artifacts"] as unknown[]).slice(0, MEMORY_LIMITS.artifacts).map((a) => {
    if (!isPlain(a)) {
      throw new EngbrainError("POLICY_REFUSED", "an artifact must be an object");
    }
    only(a, ["name", "sha256"], "an artifact");
    return { name: line(a["name"], 300, "artifact name"), ...(a["sha256"] === undefined ? {} : { sha256: String(a["sha256"]) }) };
  }) : [];
  const predicates = Array.isArray(raw["invalidation"]) ? (raw["invalidation"] as unknown[]).map((p, i): Predicate => {
    if (!isPlain(p)) {
      throw new EngbrainError("POLICY_REFUSED", `predicate ${i} must be an object`);
    }
    if (p["type"] === "source_hash" || p["type"] === "test_present") {
      only(p, ["type", "pointer"], "a predicate");
      if (!Number.isInteger(p["pointer"]) || (p["pointer"] as number) < 0 || (p["pointer"] as number) >= pointers.length) {
        throw new EngbrainError("POLICY_REFUSED", `predicate ${i} names a pointer that does not exist`);
      }
      return { type: p["type"], pointer: p["pointer"] as number };
    }
    if (p["type"] === "environment") {
      only(p, ["type", "key", "expect"], "a predicate");
      return { type: "environment", key: line(p["key"], 60, "environment key"), expect: line(p["expect"], MEMORY_LIMITS.envValue, "expected value") };
    }
    throw new EngbrainError("POLICY_REFUSED", `predicate ${i} has an unknown type`);
  }) : undefined;
  if (predicates !== undefined && predicates.length > MEMORY_LIMITS.predicates) {
    throw new EngbrainError("POLICY_REFUSED", `at most ${MEMORY_LIMITS.predicates} invalidation predicates`);
  }
  const scope = isPlain(raw["scope"]) ? raw["scope"] : {};
  only(scope, ["paths", "features", "symbols"], "scope");
  const list = (v: unknown, what: string): string[] | undefined => (v === undefined ? undefined : Array.isArray(v) && v.length <= 40 ? v.map((x) => line(x, 400, what)) : (() => { throw new EngbrainError("POLICY_REFUSED", `scope.${what} must be a short list of strings`); })());
  const links = Array.isArray(raw["links"]) ? (raw["links"] as unknown[]).slice(0, MEMORY_LIMITS.links).map((l) => {
    if (!isPlain(l) || !LINK_RELS.includes(l["rel"] as LinkRel) || typeof l["target"] !== "string" || !ID.test(l["target"])) {
      throw new EngbrainError("POLICY_REFUSED", "a link needs a rel and the id of another memory record");
    }
    only(l, ["rel", "target"], "a link");
    return { rel: l["rel"] as LinkRel, target: l["target"] };
  }) : undefined;
  const claim = ev["claim"] === undefined ? undefined : line(ev["claim"], MEMORY_LIMITS.claim, "evidence.claim");
  const record: NewMemory = {
    kind: raw["kind"] as MemoryKind, title: line(raw["title"], MEMORY_LIMITS.title, "title"), body: raw["body"], origin: raw["origin"] as MemoryOrigin,
    evidence: { pointers, type: ev["type"] as (typeof EVIDENCE_TYPES)[number], ...(claim === undefined ? {} : { claim }), ...(ev["method"] === undefined ? {} : { method: line(ev["method"], 160, "evidence.method") }), ...(Object.keys(environment).length === 0 ? {} : { environment }), ...(artifacts.length === 0 ? {} : { artifacts }) }
  };
  if (raw["validFrom"] !== undefined) { record.validFrom = iso(raw["validFrom"], "validFrom"); }
  if (raw["validTo"] !== undefined) { record.validTo = iso(raw["validTo"], "validTo"); }
  if (raw["expiresAt"] !== undefined) { record.expiresAt = iso(raw["expiresAt"], "expiresAt"); }
  if (raw["originDetail"] !== undefined) { record.originDetail = line(raw["originDetail"], 120, "originDetail"); }
  if (raw["supersedes"] !== undefined) {
    if (typeof raw["supersedes"] !== "string" || !ID.test(raw["supersedes"])) {
      throw new EngbrainError("POLICY_REFUSED", "supersedes must be a memory record id");
    }
    record.supersedes = raw["supersedes"];
  }
  const paths = list(scope["paths"], "paths");
  const features = list(scope["features"], "features");
  const symbols = list(scope["symbols"], "symbols");
  if (paths !== undefined || features !== undefined || symbols !== undefined) {
    record.scope = { ...(paths === undefined ? {} : { paths }), ...(features === undefined ? {} : { features }), ...(symbols === undefined ? {} : { symbols }) };
  }
  if (predicates !== undefined) { record.invalidation = predicates; }
  if (links !== undefined) { record.links = links; }
  return record;
}

interface Resolution { pointers: ResolvedPointer[] }

function published(db: Database.Database, oid: string): boolean {
  return prep(db, "SELECT 1 FROM git_commits WHERE commit_oid = ? AND ingest_complete = 1 AND published = 1").get(oid) !== undefined;
}

/** Binds each pointer to what it points at NOW (content hashes), or refuses: a memory record must point at real, indexed source. */
function resolvePointers(db: Database.Database, generationId: number | null, inputs: readonly PointerInput[]): Resolution {
  const pointers: ResolvedPointer[] = [];
  const fileHash = (path: string): string | null => generationId === null ? null : (prep(db, "SELECT content_hash AS h FROM generation_files WHERE generation_id = ? AND path = ? AND content_hash IS NOT NULL").get(generationId, path) as { h: string } | undefined)?.h ?? null;
  for (const p of inputs) {
    switch (p.kind) {
      case "file": {
        const h = fileHash(p.path);
        if (h === null) {
          throw new EngbrainError("POLICY_REFUSED", "a file pointer must name a file in the published index");
        }
        pointers.push({ kind: "file", path: p.path, ref: null, contentHash: h, extra: {} });
        break;
      }
      case "symbol": {
        const row = generationId === null ? undefined : prep(db, "SELECT content_hash AS h, signature_fingerprint AS sig FROM symbol_occurrences WHERE generation_id = ? AND path = ? AND qualified_name = ? AND kind != 'module' LIMIT 1").get(generationId, p.path, p.qualifiedName) as { h: string; sig: string | null } | undefined;
        if (row === undefined) {
          throw new EngbrainError("POLICY_REFUSED", "a symbol pointer must name a symbol in the published index");
        }
        pointers.push({ kind: "symbol", path: p.path, ref: p.qualifiedName, contentHash: row.h, extra: { signature: row.sig } });
        break;
      }
      case "feature": {
        let row = generationId === null ? undefined : prep(db, "SELECT entity_id AS id, content_hash AS h, path FROM feature_entities WHERE generation_id = ? AND entity_id = ?").get(generationId, p.entity) as { id: string; h: string | null; path: string | null } | undefined;
        if (row === undefined && generationId !== null && p.entity.includes(":")) {
          const rows = prep(db, "SELECT entity_id AS id, content_hash AS h, path FROM feature_entities WHERE generation_id = ? AND kind = ? AND key = ? ORDER BY entity_id LIMIT 2").all(generationId, p.entity.slice(0, p.entity.indexOf(":")), p.entity.slice(p.entity.indexOf(":") + 1)) as Array<{ id: string; h: string | null; path: string | null }>;
          if (rows.length > 1) {
            throw new EngbrainError("POLICY_REFUSED", "that feature reference matches several entities: use the entity id");
          }
          row = rows[0];
        }
        if (row === undefined) {
          throw new EngbrainError("POLICY_REFUSED", "a feature pointer must name an entity in the current feature graph");
        }
        pointers.push({ kind: "feature", path: row.path, ref: row.id, contentHash: row.h, extra: {} });
        break;
      }
      case "test": {
        const h = fileHash(p.path);
        if (h === null) {
          throw new EngbrainError("POLICY_REFUSED", "a test pointer must name a test file in the published index");
        }
        if (p.title !== undefined && generationId !== null) {
          const cases = prep(db, "SELECT attrs_json AS a FROM feature_entities WHERE generation_id = ? AND kind = 'test' AND path = ?").get(generationId, p.path) as { a: string | null } | undefined;
          const titles = cases?.a === null || cases === undefined ? [] : ((JSON.parse(cases.a) as { cases?: string[] }).cases ?? []);
          if (!titles.includes(p.title)) {
            throw new EngbrainError("POLICY_REFUSED", "the named test case is not in that test file");
          }
        }
        pointers.push({ kind: "test", path: p.path, ref: p.title ?? null, contentHash: h, extra: p.failing === true ? { failing: true } : {} });
        break;
      }
      case "commit":
        if (!published(db, p.oid)) {
          throw new EngbrainError("POLICY_REFUSED", "a commit pointer must name a commit in the history ledger (run `engbrain refresh`): memory only points at traceable history");
        }
        pointers.push({ kind: "commit", path: null, ref: p.oid, contentHash: null, extra: { role: p.role } });
        break;
      case "requirement":
        noSecrets(p.ref, "a requirement reference");
        pointers.push({ kind: "requirement", path: null, ref: p.ref, contentHash: null, extra: {} });
        break;
      case "incident":
        noSecrets(p.ref, "an incident reference");
        pointers.push({ kind: "incident", path: null, ref: p.ref, contentHash: null, extra: {} });
        break;
      case "artifact":
        pointers.push({ kind: "artifact", path: null, ref: p.name, contentHash: p.sha256 ?? null, extra: {} });
        break;
    }
  }
  return { pointers };
}

export interface MemoryRow {
  record_id: string; kind: MemoryKind; title: string; body: string; origin: MemoryOrigin; origin_detail: string | null; status: MemoryStatus; proposer: string; approver: string | null;
  approved_at: string | null; verified_by: string | null; verified_at: string | null; rejected_reason: string | null; valid_from: string; valid_to: string | null; recorded_at: string;
  superseded_at: string | null; superseded_by: string | null; expires_at: string | null; binding_revision: string | null; binding_branch: string | null; binding_overlay: string | null;
  binding_generation: number | null; scope_json: string; evidence_json: string; invalidation_json: string; content_hash: string;
}

const event = (db: Database.Database, id: string, kind: string, at: string, actor: string, detail: unknown): void =>
  void prep(db, "INSERT INTO memory_events (record_id, kind, at, actor, detail_json) VALUES (?, ?, ?, ?, ?)").run(id, kind, at, actor, detail === undefined ? null : JSON.stringify(detail));

const getRow = (db: Database.Database, id: string): MemoryRow => {
  const row = prep(db, "SELECT * FROM memory_records WHERE record_id = ?").get(id) as MemoryRow | undefined;
  if (row === undefined) {
    throw new EngbrainError("INVALID_ROOT", "no such memory record");
  }
  return row;
};

/**
 * Records a NEW memory entry (never edits an old one). Everything arrives as `candidate`: model, CI and imported records can never be authoritative on their own, and even a
 * human-proposed record needs an approving operator. Rules enforced here: pointers must resolve; a fix needs a traceable incident or failing test AND a fixing commit that is in
 * the ledger; text is refused if it looks like a secret; superseding a record closes the old one's knowledge window and leaves both.
 */
export function addMemory(db: Database.Database, input: NewMemory, ctx: { actor: Actor; now?: () => Date }): MemoryRow {
  requireRole(ctx.actor, "propose");
  const now = (ctx.now ?? (() => new Date()))();
  const recordedAt = now.toISOString();
  if (findSecretIn(input) !== null) {
    throw new EngbrainError("POLICY_REFUSED", "the record contains something that looks like a secret (title, body, evidence, pointers, environment, scope or predicates): memory never stores secrets");
  }
  const validFrom = input.validFrom ?? recordedAt;
  if (Date.parse(validFrom) > now.getTime() + 60_000) {
    throw new EngbrainError("POLICY_REFUSED", "validFrom cannot be in the future");
  }
  if (input.validTo !== undefined && input.validTo <= validFrom) {
    throw new EngbrainError("POLICY_REFUSED", "validTo must be after validFrom");
  }
  const expiresAt = input.expiresAt ?? (input.kind === "observation" ? new Date(now.getTime() + MEMORY_LIMITS.observationDays * 86_400_000).toISOString() : undefined);
  return db.transaction((): MemoryRow => {
    const generationId = currentGenerationId(db);
    const { pointers } = resolvePointers(db, generationId, input.evidence.pointers);
    const links = input.links ?? [];
    for (const l of links) {
      if (prep(db, "SELECT 1 FROM memory_records WHERE record_id = ?").get(l.target) === undefined) {
        throw new EngbrainError("POLICY_REFUSED", "a link names a memory record that does not exist");
      }
    }
    if (input.supersedes !== undefined) {
      const old = getRow(db, input.supersedes);
      if (old.status === "approved" || old.status === "verified") {
        requireRole(ctx.actor, "approve"); // retiring an authoritative record is an approver's decision, not a proposer's
      }
    }
    const commitRole = (role: string): boolean => pointers.some((p) => p.kind === "commit" && p.extra["role"] === role);
    if (input.kind === "fix") {
      const hasIncident = links.some((l) => {
        const target = prep(db, "SELECT kind, status FROM memory_records WHERE record_id = ?").get(l.target) as { kind: string; status: string };
        return l.rel === "fixes" && target.kind === "bug" && target.status !== "rejected";
      }) || pointers.some((p) => p.kind === "incident");
      const hasFailingTest = pointers.some((p) => p.kind === "test" && p.extra["failing"] === true);
      if (!hasIncident && !hasFailingTest) {
        throw new EngbrainError("POLICY_REFUSED", "a fix needs a traceable incident (a bug record it `fixes`, or an incident pointer) or a failing test pointer");
      }
      if (!commitRole("fixed")) {
        throw new EngbrainError("POLICY_REFUSED", "a fix needs a fixing commit (a commit pointer with role `fixed`) that is in the history ledger");
      }
      // when both ends are named, the fix must come AFTER the introduction in the ledger's history
      for (const fixed of pointers.filter((p) => p.kind === "commit" && p.extra["role"] === "fixed")) {
        for (const introduced of pointers.filter((p) => p.kind === "commit" && p.extra["role"] === "introduced")) {
          if (!reachableFrom(db, fixed.ref!).has(introduced.ref!)) {
            throw new EngbrainError("POLICY_REFUSED", "the fixing commit does not descend from the introducing commit in the history ledger");
          }
        }
      }
    }
    if (input.kind === "test_evidence" && !pointers.some((p) => p.kind === "test")) {
      throw new EngbrainError("POLICY_REFUSED", "test evidence needs a test pointer");
    }
    if (input.kind === "bug" && !pointers.some((p) => p.kind === "incident" || p.kind === "test" || p.kind === "commit")) {
      throw new EngbrainError("POLICY_REFUSED", "a bug needs an incident, a test or a commit pointer");
    }
    if (input.kind === "rejected_approach" && input.body.length < 10) {
      throw new EngbrainError("POLICY_REFUSED", "a rejected approach must say why (a reason in the body)");
    }
    // default invalidation: any pointer bound to source is invalidated when that source changes. A bug or a fix is a HISTORICAL fact about commits (it stays true after the code moves on):
    // it has no source predicates by default, only its place in the line of history; the evidence that something STILL holds (test evidence, decisions, claims) does.
    const predicates: Predicate[] = input.invalidation ?? (input.kind === "bug" || input.kind === "fix" ? [] : pointers).flatMap((p, i): Predicate[] => (p.contentHash !== null && ["file", "symbol", "feature"].includes(p.kind) ? [{ type: "source_hash", pointer: i }] : p.kind === "test" ? [{ type: "test_present", pointer: i }] : []));
    const checkpoint = prep(db, "SELECT overlay_hash AS o, branch_label AS b FROM history_checkpoints WHERE ref_key = 'HEAD'").get() as { o: string | null; b: string | null } | undefined;
    const gen = generationId === null ? undefined : prep(db, "SELECT revision, branch_label AS b FROM generations WHERE id = ?").get(generationId) as { revision: string | null; b: string | null } | undefined;
    const scope = input.scope ?? {};
    const evidence = { ...input.evidence, pointers: pointers.map((p) => ({ kind: p.kind, path: p.path, ref: p.ref, contentHash: p.contentHash, ...p.extra })) };
    const canonical = { kind: input.kind, title: input.title, body: input.body, origin: input.origin, proposer: ctx.actor.id, validFrom, validTo: input.validTo ?? null, scope, evidence, predicates };
    const id = `mem_${randomBytes(8).toString("hex")}`;
    prep(db, 
      `INSERT INTO memory_records (record_id, kind, title, body, origin, origin_detail, status, proposer, valid_from, valid_to, recorded_at, expires_at, binding_revision, binding_branch, binding_overlay, binding_generation,
         scope_json, evidence_json, invalidation_json, content_hash) VALUES (?, ?, ?, ?, ?, ?, 'candidate', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(id, input.kind, input.title, input.body, input.origin, input.originDetail ?? null, ctx.actor.id, validFrom, input.validTo ?? null, recordedAt, expiresAt ?? null, gen?.revision ?? null, gen?.b ?? checkpoint?.b ?? null,
      checkpoint?.o ?? null, generationId, JSON.stringify(scope), JSON.stringify(evidence), JSON.stringify(predicates), hashOf(canonical));
    const insertPointer = prep(db, "INSERT INTO memory_pointers (record_id, ordinal, kind, path, ref, content_hash, extra_json) VALUES (?, ?, ?, ?, ?, ?, ?)");
    pointers.forEach((p, i) => insertPointer.run(id, i, p.kind, p.path, p.ref, p.contentHash, JSON.stringify(p.extra)));
    for (const l of links) {
      prep(db, "INSERT OR IGNORE INTO memory_links (record_id, rel, target_id) VALUES (?, ?, ?)").run(id, l.rel, l.target);
    }
    event(db, id, "recorded", recordedAt, ctx.actor.id, { origin: input.origin });
    if (input.supersedes !== undefined) {
      const old = getRow(db, input.supersedes);
      if (old.superseded_at !== null) {
        throw new EngbrainError("POLICY_REFUSED", "that record is already superseded");
      }
      prep(db, "UPDATE memory_records SET superseded_at = ?, superseded_by = ? WHERE record_id = ?").run(recordedAt, id, old.record_id);
      prep(db, "INSERT OR IGNORE INTO memory_links (record_id, rel, target_id) VALUES (?, 'supersedes', ?)").run(id, old.record_id);
      event(db, old.record_id, "superseded", recordedAt, ctx.actor.id, { by: id });
    }
    return getRow(db, id);
  }).immediate();
}

/** An authorised operator approves a candidate. A model-origin record additionally needs independent substantiation (a non-model, approved/verified record linked as `substantiated_by`). */
export function approveMemory(db: Database.Database, id: string, ctx: { actor: Actor; now?: () => Date; distinctApprover?: boolean; evaluate: (row: MemoryRow) => { state: string } }): MemoryRow {
  requireRole(ctx.actor, "approve");
  const at = (ctx.now ?? (() => new Date()))().toISOString();
  return db.transaction((): MemoryRow => {
    const row = getRow(db, id);
    if (row.status !== "candidate") {
      throw new EngbrainError("POLICY_REFUSED", `only a candidate can be approved (this one is ${row.status})`);
    }
    if (row.superseded_at !== null) {
      throw new EngbrainError("POLICY_REFUSED", "a superseded record cannot be approved");
    }
    if (ctx.distinctApprover === true && ctx.actor.id === row.proposer) {
      throw new EngbrainError("POLICY_REFUSED", "policy requires the approver to differ from the proposer");
    }
    const evidence = JSON.parse(row.evidence_json) as { pointers: Array<{ kind: string }>; type: string };
    if (!evidence.pointers.some((p) => ["file", "symbol", "feature", "test", "commit"].includes(p.kind))) {
      throw new EngbrainError("POLICY_REFUSED", "a record without a source pointer cannot be approved");
    }
    if (ctx.evaluate(row).state !== "applies") {
      throw new EngbrainError("POLICY_REFUSED", "the record's evidence does not currently apply (changed, deleted, out of scope or unknown): re-record it against current evidence");
    }
    const predicates = JSON.parse(row.invalidation_json) as unknown[];
    if (predicates.length === 0 && row.kind !== "bug" && row.kind !== "fix") {
      throw new EngbrainError("POLICY_REFUSED", "a record with no invalidation predicate would never go stale: give it a source, test or environment predicate before approval (only bugs and fixes are historical)");
    }
    if (row.kind === "fix") {
      const bugs = prep(db, "SELECT r.status AS s FROM memory_links l JOIN memory_records r ON r.record_id = l.target_id WHERE l.record_id = ? AND l.rel = 'fixes'").all(id) as Array<{ s: string }>;
      if (bugs.length > 0 && !bugs.some((b) => b.s === "approved" || b.s === "verified")) {
        throw new EngbrainError("POLICY_REFUSED", "a fix cannot be approved before the bug it fixes is approved");
      }
    }
    if (needsSubstantiation(row)) {
      const ownPointers = new Set((JSON.parse(row.evidence_json) as { pointers: Array<{ kind: string; path: string | null; ref: string | null }> }).pointers.filter((p) => p.kind !== "commit").map((p) => `${p.path ?? ""}#${p.ref ?? ""}`));
      const ownPaths = new Set((JSON.parse(row.evidence_json) as { pointers: Array<{ path: string | null }> }).pointers.map((p) => p.path).filter((p): p is string => p !== null));
      const substantiated = (prep(db, "SELECT target_id AS t FROM memory_links WHERE record_id = ? AND rel = 'substantiated_by'").all(id) as Array<{ t: string }>).some((l) => {
        const other = prep(db, "SELECT * FROM memory_records WHERE record_id = ?").get(l.t) as MemoryRow | undefined;
        if (other === undefined || needsSubstantiation(other) || other.proposer === row.proposer || !(other.status === "approved" || other.status === "verified") || ctx.evaluate(other).state !== "applies") {
          return false;
        }
        // relevant: the substantiating record points at the same source (a file the claim names, or the same symbol)
        const theirs = (JSON.parse(other.evidence_json) as { pointers: Array<{ kind: string; path: string | null; ref: string | null }> }).pointers.filter((p) => p.kind !== "commit");
        return theirs.some((p) => ownPointers.has(`${p.path ?? ""}#${p.ref ?? ""}`) || (p.path !== null && ownPaths.has(p.path)));
      });
      if (!substantiated) {
        throw new EngbrainError("POLICY_REFUSED", "model-derived content stays a candidate until independently substantiated: link it (`substantiated_by`) to an approved or verified record from a different proposer, not model-derived, that points at the same source and still applies");
      }
    }
    prep(db, "UPDATE memory_records SET status = 'approved', approver = ?, approved_at = ? WHERE record_id = ?").run(ctx.actor.id, at, id);
    event(db, id, "approved", at, ctx.actor.id, undefined);
    return getRow(db, id);
  }).immediate();
}

/** `verified` is stronger than `approved`: an operator with the verify role confirms test or CI evidence that currently applies. */
export function verifyMemory(db: Database.Database, id: string, ctx: { actor: Actor; now?: () => Date; distinctApprover?: boolean; evaluate: (row: MemoryRow) => { state: string }; ciSupports?: (row: MemoryRow) => boolean }): MemoryRow {
  requireRole(ctx.actor, "verify");
  const at = (ctx.now ?? (() => new Date()))().toISOString();
  return db.transaction((): MemoryRow => {
    const row = getRow(db, id);
    if (row.status !== "approved") {
      throw new EngbrainError("POLICY_REFUSED", "only an approved record can be verified");
    }
    if (ctx.distinctApprover === true && (ctx.actor.id === row.proposer || ctx.actor.id === row.approver)) {
      throw new EngbrainError("POLICY_REFUSED", "policy requires the verifier to differ from the proposer and the approver");
    }
    if (!(JSON.parse(row.invalidation_json) as Array<{ type: string }>).some((p) => p.type === "test_present")) {
      throw new EngbrainError("POLICY_REFUSED", "verification needs a `test_present` predicate so the verification goes stale when the test changes or is deleted");
    }
    const evidence = JSON.parse(row.evidence_json) as { pointers: Array<{ kind: string }>; type: string };
    if (!["test", "ci"].includes(evidence.type) || !evidence.pointers.some((p) => p.kind === "test")) {
      throw new EngbrainError("POLICY_REFUSED", "verification needs test or CI evidence with a test pointer");
    }
    if (evidence.type === "ci" && ctx.ciSupports?.(row) !== true) {
      throw new EngbrainError("POLICY_REFUSED", "CI evidence needs an artifact pointer to a signed or accepted evidence import, still applying, in which the named test passed (quarantined imports count for nothing)");
    }
    if (ctx.evaluate(row).state !== "applies") {
      throw new EngbrainError("POLICY_REFUSED", "the evidence no longer applies: it cannot be verified");
    }
    prep(db, "UPDATE memory_records SET status = 'verified', verified_by = ?, verified_at = ? WHERE record_id = ?").run(ctx.actor.id, at, id);
    event(db, id, "verified", at, ctx.actor.id, undefined);
    return getRow(db, id);
  }).immediate();
}

export function rejectMemory(db: Database.Database, id: string, ctx: { actor: Actor; reason: string; now?: () => Date }): MemoryRow {
  requireRole(ctx.actor, "approve");
  const reason = line(ctx.reason, MEMORY_LIMITS.reason, "reason");
  noSecrets(reason, "the reason");
  const at = (ctx.now ?? (() => new Date()))().toISOString();
  return db.transaction((): MemoryRow => {
    const row = getRow(db, id);
    if (row.status === "rejected") {
      throw new EngbrainError("POLICY_REFUSED", "already rejected");
    }
    prep(db, "UPDATE memory_records SET status = 'rejected', rejected_reason = ? WHERE record_id = ?").run(reason, id);
    event(db, id, "rejected", at, ctx.actor.id, { reason });
    return getRow(db, id);
  }).immediate();
}

/** The environment assumptions that `environment` predicates compare against. History is kept; the latest value per key is current. */
export function setEnvironment(db: Database.Database, key: string, value: string, ctx: { actor: Actor; now?: () => Date }): void {
  requireRole(ctx.actor, "admin");
  line(key, 60, "environment key");
  line(value, MEMORY_LIMITS.envValue, "environment value");
  if (findSecretIn({ [key]: value }) !== null) {
    throw new EngbrainError("POLICY_REFUSED", "the environment key or value looks like a secret: memory never stores secrets");
  }
  prep(db, "INSERT INTO memory_environment (key, value, recorded_at, recorded_by) VALUES (?, ?, ?, ?)").run(key, value, (ctx.now ?? (() => new Date()))().toISOString(), ctx.actor.id);
}

/**
 * Writes an `invalidated` event for records whose predicates currently fail on THIS line of history. It records an observation, it does not demote: a record's stored status is never changed here
 * (standing is computed on every read), so invalidating on a descendant branch cannot damage the record for the branch it was made on. One event per (record, checkpoint).
 */
export function recordInvalidations(db: Database.Database, ctx: { actor: Actor; now?: () => Date; evaluate: (row: MemoryRow) => { state: string; reasons: string[] } }): number {
  requireRole(ctx.actor, "propose");
  const at = (ctx.now ?? (() => new Date()))().toISOString();
  return db.transaction((): number => {
    let changed = 0;
    const checkpoint = (prep(db, "SELECT processed_oid AS oid FROM history_checkpoints WHERE ref_key = 'HEAD'").get() as { oid: string | null } | undefined)?.oid ?? null;
    for (const row of prep(db, "SELECT * FROM memory_records WHERE status IN ('approved', 'verified') AND superseded_at IS NULL").all() as MemoryRow[]) {
      const standing = ctx.evaluate(row);
      if (standing.state !== "stale") {
        continue;
      }
      const last = prep(db, "SELECT detail_json AS d FROM memory_events WHERE record_id = ? AND kind = 'invalidated' ORDER BY event_id DESC LIMIT 1").get(row.record_id) as { d: string | null } | undefined;
      if (last?.d != null && (JSON.parse(last.d) as { checkpoint?: string | null }).checkpoint === checkpoint) {
        continue;
      }
      event(db, row.record_id, "invalidated", at, ctx.actor.id, { reasons: standing.reasons.slice(0, 10), checkpoint, status: row.status });
      changed += 1;
    }
    return changed;
  }).immediate();
}
