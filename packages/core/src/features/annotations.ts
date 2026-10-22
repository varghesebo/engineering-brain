import { createHash } from "node:crypto";
import { lstatSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type Database from "better-sqlite3";
import { currentGenerationId } from "../store/generations.js";
import { STORE_DIR_NAME } from "../store/store.js";
import type { NodeRecord } from "./queries.js";

/**
 * User-authored feature annotations: strictly validated JSON files in `.engineering-brain/features/` (a local, gitignored, controlled directory; never the repository
 * tree). They DESCRIBE boundaries and constraints; they never create entities or edges and never replace what the code says: a member that the code does not
 * contain stays "documented but not found". Applied at READ time, so they are always shown separately from generated facts (trust `annotation`).
 */
export const ANNOTATION_LIMITS = { files: 100, fileBytes: 65_536, features: 200, members: 200, constraints: 50, text: 300, description: 1000 } as const;
const ID = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const KINDS = new Set(["route", "ui_route", "api_call", "api_operation", "event", "db_table", "db_query", "job", "test"]);

export interface AnnotationSelector { kind?: string; key?: string; path?: string; symbol?: string }
export interface AnnotationFeature {
  id: string;
  name: string;
  description: string | null;
  members: Array<{ selector: AnnotationSelector; role: string | null }>;
  constraints: Array<{ statement: string; source: string }>;
  file: string;
}
export interface LoadedAnnotations {
  directory: string | null;
  files: Array<{ name: string; sha256: string; features: number }>;
  features: AnnotationFeature[];
  problems: Array<{ file: string; problem: string }>;
}

const isPlain = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const text = (v: unknown, max: number): string | null => (typeof v === "string" && v.length >= 1 && v.length <= max && !/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(v) ? v : null);

function validateFeature(raw: unknown, file: string): { feature: AnnotationFeature } | { problem: string } {
  if (!isPlain(raw)) {
    return { problem: "a feature must be an object" };
  }
  const allowed = new Set(["id", "name", "description", "members", "constraints"]);
  const extra = Object.keys(raw).find((k) => !allowed.has(k));
  if (extra !== undefined) {
    return { problem: `unknown property "${extra.slice(0, 40)}"` };
  }
  const id = text(raw["id"], 64);
  const name = text(raw["name"], 120);
  if (id === null || !ID.test(id) || name === null) {
    return { problem: "id (lowercase letters, digits, . _ -) and name are required" };
  }
  const description = raw["description"] === undefined ? null : text(raw["description"], ANNOTATION_LIMITS.description);
  if (raw["description"] !== undefined && description === null) {
    return { problem: `${id}: description is invalid` };
  }
  if (!Array.isArray(raw["members"]) || raw["members"].length === 0 || raw["members"].length > ANNOTATION_LIMITS.members) {
    return { problem: `${id}: members must be a non-empty array of at most ${ANNOTATION_LIMITS.members}` };
  }
  const members: AnnotationFeature["members"] = [];
  for (const m of raw["members"] as unknown[]) {
    if (!isPlain(m) || !isPlain(m["selector"]) || Object.keys(m).some((k) => k !== "selector" && k !== "role")) {
      return { problem: `${id}: a member needs a selector object (and optionally a role)` };
    }
    const sel = m["selector"];
    if (Object.keys(sel).some((k) => !["kind", "key", "path", "symbol"].includes(k)) || Object.keys(sel).length === 0) {
      return { problem: `${id}: a selector accepts kind, key, path or symbol only` };
    }
    const selector: AnnotationSelector = {};
    for (const k of ["kind", "key", "path", "symbol"] as const) {
      if (sel[k] !== undefined) {
        const v = text(sel[k], k === "path" || k === "symbol" ? 1024 : ANNOTATION_LIMITS.text);
        if (v === null || (k === "kind" && !KINDS.has(v)) || (k === "path" && (v.startsWith("/") || v.includes("..") || v.includes("\\")))) {
          return { problem: `${id}: selector ${k} is invalid` };
        }
        selector[k] = v;
      }
    }
    if (selector.kind !== undefined && selector.key === undefined && selector.path === undefined && selector.symbol === undefined) {
      return { problem: `${id}: a kind alone selects nothing specific; add a key, path or symbol` };
    }
    members.push({ selector, role: m["role"] === undefined ? null : text(m["role"], 60) });
  }
  const constraints: AnnotationFeature["constraints"] = [];
  if (raw["constraints"] !== undefined) {
    if (!Array.isArray(raw["constraints"]) || raw["constraints"].length > ANNOTATION_LIMITS.constraints) {
      return { problem: `${id}: constraints must be an array` };
    }
    for (const c of raw["constraints"] as unknown[]) {
      const statement = isPlain(c) ? text(c["statement"], ANNOTATION_LIMITS.text) : null;
      const source = isPlain(c) ? text(c["source"], ANNOTATION_LIMITS.text) : null;
      if (statement === null || source === null) {
        return { problem: `${id}: every constraint needs a statement and the documented source it comes from` };
      }
      constraints.push({ statement, source });
    }
  }
  return { feature: { id, name, description, members, constraints, file } };
}

export function loadAnnotations(root: string): LoadedAnnotations {
  const result: LoadedAnnotations = { directory: null, files: [], features: [], problems: [] };
  const dir = join(root, STORE_DIR_NAME, "features");
  let entries: string[];
  try {
    const stat = lstatSync(dir);
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      result.problems.push({ file: "features", problem: "the annotations directory is not a real directory: ignored" });
      return result;
    }
    entries = readdirSync(dir).filter((n) => n.endsWith(".json")).sort();
  } catch {
    return result;
  }
  result.directory = dir;
  if (entries.length > ANNOTATION_LIMITS.files) {
    result.problems.push({ file: "features", problem: `more than ${ANNOTATION_LIMITS.files} annotation files: the rest are ignored` });
    entries = entries.slice(0, ANNOTATION_LIMITS.files);
  }
  const seen = new Set<string>();
  for (const name of entries) {
    const path = join(dir, name);
    let data: Buffer;
    try {
      const stat = lstatSync(path);
      if (!stat.isFile() || stat.size > ANNOTATION_LIMITS.fileBytes) {
        result.problems.push({ file: name, problem: "not a regular file, or larger than 64 KiB: ignored" });
        continue;
      }
      data = readFileSync(path);
    } catch {
      result.problems.push({ file: name, problem: "unreadable: ignored" });
      continue;
    }
    let doc: unknown;
    try {
      doc = JSON.parse(data.toString("utf8"));
    } catch {
      result.problems.push({ file: name, problem: "not valid JSON: ignored" });
      continue;
    }
    if (!isPlain(doc) || doc["schemaVersion"] !== 1 || !Array.isArray(doc["features"]) || Object.keys(doc).some((k) => k !== "schemaVersion" && k !== "features")) {
      result.problems.push({ file: name, problem: "expected { schemaVersion: 1, features: [...] }: ignored" });
      continue;
    }
    let accepted = 0;
    for (const raw of (doc["features"] as unknown[]).slice(0, ANNOTATION_LIMITS.features)) {
      const v = validateFeature(raw, name);
      if ("problem" in v) {
        result.problems.push({ file: name, problem: v.problem });
      } else if (seen.has(v.feature.id)) {
        result.problems.push({ file: name, problem: `${v.feature.id}: duplicate feature id (the first definition wins)` });
      } else {
        seen.add(v.feature.id);
        result.features.push(v.feature);
        accepted += 1;
      }
    }
    result.files.push({ name, sha256: createHash("sha256").update(data).digest("hex"), features: accepted });
  }
  return result;
}

export interface AnnotatedMember {
  selector: AnnotationSelector;
  role: string | null;
  status: "resolved" | "ambiguous" | "documented_but_not_found";
  entities: NodeRecord[];
}
export interface AnnotatedFeatureView {
  generationId: number | null;
  id: string;
  name: string;
  description: string | null;
  source: "annotation";
  trust: "annotation";
  file: string;
  members: AnnotatedMember[];
  constraints: Array<{ statement: string; source: string; verified: false }>;
  notFound: number;
  note: string;
}

/** Matches each documented member against the CURRENT generation. Nothing is created from the annotation: unmatched members are reported as not found. */
export function resolveAnnotations(db: Database.Database, annotations: readonly AnnotationFeature[]): AnnotatedFeatureView[] {
  return db.transaction((): AnnotatedFeatureView[] => {
    const generationId = currentGenerationId(db);
    const entityStmt = db.prepare(
      `SELECT entity_id AS id, kind, name, path, start_line AS startLine, package_dir AS package, mechanism, certainty, trust, valid_from_generation AS validFromGeneration FROM feature_entities
       WHERE generation_id = ? AND (? IS NULL OR kind = ?) AND (? IS NULL OR key = ?) AND (? IS NULL OR path = ?) ORDER BY entity_id LIMIT 20`
    );
    return annotations.map((a): AnnotatedFeatureView => {
      const members = a.members.map((m): AnnotatedMember => {
        let entities: NodeRecord[] = [];
        if (generationId !== null) {
          if (m.selector.symbol !== undefined) {
            const cut = m.selector.symbol.lastIndexOf("#");
            const path = m.selector.symbol.slice(0, cut);
            const q = m.selector.symbol.slice(cut + 1);
            const exists = cut > 0 && db.prepare("SELECT 1 FROM symbol_occurrences WHERE generation_id = ? AND path = ? AND qualified_name = ? AND kind != 'module'").get(generationId, path, q) !== undefined;
            entities = exists ? [{ id: `sym:${path}#${q}`, kind: "symbol", name: q, path, startLine: null, package: null, mechanism: "symbol_resolution", certainty: null, trust: null, validFromGeneration: null }] : [];
          } else {
            const s = m.selector;
            entities = entityStmt.all(generationId, s.kind ?? null, s.kind ?? null, s.key ?? null, s.key ?? null, s.path ?? null, s.path ?? null) as NodeRecord[];
          }
        }
        return { selector: m.selector, role: m.role, status: entities.length === 0 ? "documented_but_not_found" : entities.length === 1 ? "resolved" : "ambiguous", entities };
      });
      return {
        generationId, id: a.id, name: a.name, description: a.description, source: "annotation", trust: "annotation", file: a.file, members,
        constraints: a.constraints.map((c) => ({ ...c, verified: false as const })), notFound: members.filter((m) => m.status === "documented_but_not_found").length,
        note: "Human-authored. Members are matched against the current code; the annotation creates no entity or edge, and its constraints are documented, not verified."
      };
    });
  })();
}
