import type Database from "better-sqlite3";
import { CODE_EXTRACTOR_LIKE } from "./codeExtractor.js";
import type { ParameterFact, SymbolKind } from "./extractor.js";
import { currentGenerationId } from "./store/generations.js";

/** Read-only queries over the PUBLISHED generation. They never reparse, never touch git or the working tree. */
export interface SymbolRecord {
  path: string;
  kind: SymbolKind;
  name: string;
  qualifiedName: string;
  parent: string | null;
  exported: boolean;
  exportName: string | null;
  anonymous: boolean;
  startLine: number;
  startColumn: number;
  endLine: number;
  endColumn: number;
  startByte: number;
  endByte: number;
  parameters: ParameterFact[] | null;
  signatureFingerprint: string | null;
  symbolKey: string;
  contentHash: string;
}

export interface SymbolQuery {
  file?: string;
  search?: string;
  kind?: SymbolKind;
  exportedOnly?: boolean;
  limit?: number;
}

export interface QueryResult<T> {
  generationId: number | null;
  rows: T[];
  truncated: boolean;
}

const DEFAULT_LIMIT = 200;
const MAX_LIMIT = 5000;
const escapeLike = (text: string): string => text.replace(/[\\%_]/g, (c) => `\\${c}`);
const clampLimit = (limit: number | undefined): number => Math.min(Math.max(1, Math.floor(limit ?? DEFAULT_LIMIT)), MAX_LIMIT);

export function findSymbols(db: Database.Database, query: SymbolQuery = {}): QueryResult<SymbolRecord> {
  const limit = clampLimit(query.limit);
  return db.transaction((): QueryResult<SymbolRecord> => {
    const generationId = currentGenerationId(db);
    if (generationId === null) {
      return { generationId: null, rows: [], truncated: false };
    }
    const where = ["o.generation_id = ?", "o.extractor_id LIKE ?"];
    const params: unknown[] = [generationId, CODE_EXTRACTOR_LIKE];
    if (query.file !== undefined) {
      where.push("o.path = ?");
      params.push(query.file);
    }
    if (query.search !== undefined && query.search !== "") {
      where.push("(o.name LIKE ? ESCAPE '\\' OR o.qualified_name LIKE ? ESCAPE '\\')");
      const pattern = `%${escapeLike(query.search)}%`;
      params.push(pattern, pattern);
    }
    if (query.kind !== undefined) {
      where.push("o.kind = ?");
      params.push(query.kind);
    } else {
      where.push("o.kind != 'module'");
    }
    if (query.exportedOnly === true) {
      where.push("o.exported = 1");
    }
    const rows = db.prepare(
      `SELECT o.path AS path, o.kind AS kind, o.name AS name, o.qualified_name AS qualifiedName, p.qualified_name AS parent,
              o.exported AS exported, o.export_name AS exportName, o.anonymous AS anonymous,
              o.start_line AS startLine, o.start_col AS startColumn, o.end_line AS endLine, o.end_col AS endColumn,
              o.start_byte AS startByte, o.end_byte AS endByte, o.parameters_json AS parametersJson,
              o.signature_fingerprint AS signatureFingerprint, o.symbol_key AS symbolKey, o.content_hash AS contentHash
       FROM symbol_occurrences o
       LEFT JOIN symbols p ON p.content_hash = o.content_hash AND p.extractor_id = o.extractor_id
         AND p.extractor_version = o.extractor_version AND p.local_id = o.parent_local_id
       WHERE ${where.join(" AND ")}
       ORDER BY o.path, o.start_byte, o.local_id
       LIMIT ?`
    ).all(...params, limit + 1) as Array<Omit<SymbolRecord, "parameters" | "exported" | "anonymous"> & { exported: number; anonymous: number; parametersJson: string | null }>;
    const truncated = rows.length > limit;
    return {
      generationId,
      truncated,
      rows: rows.slice(0, limit).map(({ parametersJson, exported, anonymous, ...rest }) => ({
        ...rest, exported: exported === 1, anonymous: anonymous === 1, parameters: parametersJson === null ? null : (JSON.parse(parametersJson) as ParameterFact[])
      }))
    };
  })();
}

export interface ModuleEdgeRecord {
  from: string;
  kind: string;
  specifier: string | null;
  resolvedPath: string | null;
  resolution: string;
  reason: string;
  line: number;
}

export interface EdgeQuery {
  /** Edges leaving this file. */
  from?: string;
  /** Edges arriving at this file (who imports it). */
  to?: string;
  resolution?: string;
  limit?: number;
}

export function findModuleEdges(db: Database.Database, query: EdgeQuery = {}): QueryResult<ModuleEdgeRecord> {
  const limit = clampLimit(query.limit);
  return db.transaction((): QueryResult<ModuleEdgeRecord> => {
    const generationId = currentGenerationId(db);
    if (generationId === null) {
      return { generationId: null, rows: [], truncated: false };
    }
    const where = ["generation_id = ?"];
    const params: unknown[] = [generationId];
    if (query.from !== undefined) {
      where.push("from_path = ?");
      params.push(query.from);
    }
    if (query.to !== undefined) {
      where.push("resolved_path = ?");
      params.push(query.to);
    }
    if (query.resolution !== undefined) {
      where.push("resolution = ?");
      params.push(query.resolution);
    }
    const rows = db.prepare(
      `SELECT from_path AS "from", edge_kind AS kind, specifier, resolved_path AS resolvedPath, resolution, reason, line
       FROM module_edges WHERE ${where.join(" AND ")} ORDER BY from_path, ordinal LIMIT ?`
    ).all(...params, limit + 1) as ModuleEdgeRecord[];
    return { generationId, rows: rows.slice(0, limit), truncated: rows.length > limit };
  })();
}
