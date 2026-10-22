import { createHash } from "node:crypto";
import type Database from "better-sqlite3";
import { CODE_EXTRACTOR_LIKE } from "./codeExtractor.js";
import { EngbrainError } from "./errors.js";
import { currentGenerationId } from "./store/generations.js";

/**
 * Ranked keyword search over the PUBLISHED generation: symbol names and file paths. Every hit says why it scored (`why`), scores are
 * integer arithmetic over documented weights, and ordering is total (score, path, line, key), so the same index and query give the same page.
 * No embeddings, no model call, no SQLite FTS5 (see docs/context-and-mcp.md: measured substring scans are fast enough at the benchmarked sizes).
 * Only indexed files are searchable: excluded files (secrets, binaries, generated, ignored) have no content hash and never appear.
 */
export const SEARCH_LIMITS = { maxTerms: 8, termLength: 64, candidatesPerTerm: 2000, maxPage: 100, maxOffset: 5000, queryLength: 500 } as const;

const STOPWORDS = new Set([
  "the", "a", "an", "and", "or", "of", "to", "in", "on", "for", "with", "from", "by", "is", "are", "be", "this", "that", "it", "as", "at", "into", "how", "what", "where",
  "when", "why", "which", "who", "do", "does", "can", "should", "add", "fix", "make", "update", "change", "use", "using", "new", "get", "set", "need", "want", "please"
]);

export interface SearchHit {
  type: "symbol" | "file";
  path: string;
  symbolKey: string | null;
  name: string | null;
  qualifiedName: string | null;
  kind: string | null;
  exported: boolean | null;
  startLine: number | null;
  endLine: number | null;
  score: number;
  why: string[];
  contentHash: string;
  extractor: string | null;
  extractorVersion: string | null;
}

export interface SearchResult {
  generationId: number | null;
  terms: string[];
  hits: SearchHit[];
  totalMatches: number;
  truncated: boolean;
  nextCursor: string | null;
  /** True when a per-term candidate cap was reached: lower-ranked matches may be missing. */
  candidateCapReached: boolean;
  /** Where this page started and the query identity: lets a caller that returns FEWER hits than a page build the cursor that resumes after the last one it returned. */
  offset: number;
  queryHash: string;
}

export interface SearchOptions {
  query: string;
  limit?: number;
  cursor?: string | null;
  kinds?: readonly string[];
  /** Restrict to paths under this directory prefix (repo-relative, no leading slash). */
  pathPrefix?: string;
}

/** Search terms: identifiers kept whole and split on camelCase/snake_case/digits, lower-cased, stop words dropped, bounded. */
export function extractTerms(text: string): string[] {
  const terms: string[] = [];
  const add = (raw: string): void => {
    const term = raw.toLowerCase().slice(0, SEARCH_LIMITS.termLength);
    if (term.length >= 2 && !STOPWORDS.has(term) && !terms.includes(term) && terms.length < SEARCH_LIMITS.maxTerms) {
      terms.push(term);
    }
  };
  for (const token of text.slice(0, SEARCH_LIMITS.queryLength).match(/[A-Za-z_$][\w$./-]*/g) ?? []) {
    const word = token.replace(/^[./-]+|[./-]+$/g, "");
    add(word);
    if (/[A-Z_/.-]/.test(word.slice(1))) {
      for (const part of word.split(/(?<=[a-z0-9])(?=[A-Z])|[_/.-]+/)) {
        add(part);
      }
    }
  }
  return terms;
}

const escapeLike = (text: string): string => text.replace(/[\\%_]/g, (c) => `\\${c}`);

interface Candidate extends SearchHit {
  matched: Set<string>;
}

function bump(c: Candidate, term: string, points: number, reason: string): void {
  c.score += points;
  c.matched.add(term);
  c.why.push(reason);
}

interface SymbolRow {
  path: string; kind: string; name: string; q: string; exported: number; startLine: number; endLine: number; key: string; hash: string; extractor: string; extractorVersion: string;
}

export function encodeCursor(generationId: number, queryHash: string, offset: number): string {
  return Buffer.from(JSON.stringify({ g: generationId, q: queryHash, o: offset }), "utf8").toString("base64url");
}

export function decodeCursor(cursor: string, generationId: number, queryHash: string): number {
  let parsed: { g?: unknown; q?: unknown; o?: unknown };
  try {
    parsed = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8")) as typeof parsed;
  } catch {
    throw new EngbrainError("POLICY_REFUSED", "invalid cursor");
  }
  if (typeof parsed !== "object" || parsed === null || typeof parsed.o !== "number" || !Number.isInteger(parsed.o) || parsed.o < 0 || parsed.o > SEARCH_LIMITS.maxOffset || typeof parsed.g !== "number" || typeof parsed.q !== "string") {
    throw new EngbrainError("POLICY_REFUSED", "invalid cursor");
  }
  if (parsed.q !== queryHash) {
    throw new EngbrainError("POLICY_REFUSED", "cursor belongs to a different query");
  }
  if (parsed.g !== generationId) {
    throw new EngbrainError("POLICY_REFUSED", "cursor expired: the index was updated since it was issued; repeat the query without a cursor");
  }
  return parsed.o;
}

export const queryHashOf = (...parts: readonly string[]): string => createHash("sha256").update(parts.join("\0")).digest("hex").slice(0, 16);

export function searchCode(db: Database.Database, options: SearchOptions): SearchResult {
  const limit = Math.min(Math.max(1, Math.floor(options.limit ?? 20)), SEARCH_LIMITS.maxPage);
  const terms = extractTerms(options.query);
  return db.transaction((): SearchResult => {
    const generationId = currentGenerationId(db);
    if (generationId === null || terms.length === 0) {
      return { generationId, terms, hits: [], totalMatches: 0, truncated: false, nextCursor: null, candidateCapReached: false, offset: 0, queryHash: "" };
    }
    const queryHash = queryHashOf(terms.join(" "), (options.kinds ?? []).join(","), options.pathPrefix ?? "");
    const offset = options.cursor === undefined || options.cursor === null ? 0 : decodeCursor(options.cursor, generationId, queryHash);
    const candidates = new Map<string, Candidate>();
    let capReached = false;
    const prefix = options.pathPrefix === undefined || options.pathPrefix === "" ? null : `${escapeLike(options.pathPrefix.replace(/\/+$/, ""))}/%`;
    const kindFilter = options.kinds !== undefined && options.kinds.length > 0 ? ` AND kind IN (${options.kinds.map(() => "?").join(",")})` : "";
    const symbolSql = db.prepare(
      `SELECT path, kind, name, qualified_name AS q, exported, start_line AS startLine, end_line AS endLine, symbol_key AS key, content_hash AS hash, extractor_id AS extractor, extractor_version AS extractorVersion
       FROM symbol_occurrences
       WHERE generation_id = ? AND extractor_id LIKE ? AND kind != 'module' AND (name LIKE ? ESCAPE '\\' OR qualified_name LIKE ? ESCAPE '\\')${kindFilter}
         ${prefix === null ? "" : "AND path LIKE ? ESCAPE '\\'"}
       LIMIT ?`
    );
    const fileSql = db.prepare(
      `SELECT gf.path AS path, gf.content_hash AS hash FROM generation_files gf
       WHERE gf.generation_id = ? AND gf.content_hash IS NOT NULL AND gf.path LIKE ? ESCAPE '\\' ${prefix === null ? "" : "AND gf.path LIKE ? ESCAPE '\\'"}
       LIMIT ?`
    );
    for (const term of terms) {
      const pattern = `%${escapeLike(term)}%`;
      const params: unknown[] = [generationId, CODE_EXTRACTOR_LIKE, pattern, pattern, ...(options.kinds ?? []), ...(prefix === null ? [] : [prefix]), SEARCH_LIMITS.candidatesPerTerm];
      const symbols = symbolSql.all(...params) as SymbolRow[];
      capReached = capReached || symbols.length >= SEARCH_LIMITS.candidatesPerTerm;
      for (const row of symbols) {
        const id = `${row.path}#${row.key}`;
        let c = candidates.get(id);
        if (c === undefined) {
          c = {
            type: "symbol", path: row.path, symbolKey: row.key, name: row.name, qualifiedName: row.q, kind: row.kind, exported: row.exported === 1,
            startLine: row.startLine, endLine: row.endLine, score: row.exported === 1 ? 5 : 0, why: row.exported === 1 ? ["exported"] : [], contentHash: row.hash, extractor: row.extractor, extractorVersion: row.extractorVersion, matched: new Set()
          };
          candidates.set(id, c);
        }
        const name = row.name.toLowerCase();
        if (name === term) {
          bump(c, term, 50, `name equals "${term}"`);
        } else if (name.startsWith(term)) {
          bump(c, term, 30, `name starts with "${term}"`);
        } else if (name.includes(term)) {
          bump(c, term, 15, `name contains "${term}"`);
        } else {
          bump(c, term, 8, `qualified name contains "${term}"`);
        }
        if (row.path.toLowerCase().includes(term)) {
          bump(c, term, 5, `path contains "${term}"`);
        }
      }
      const files = fileSql.all(generationId, pattern, ...(prefix === null ? [] : [prefix]), SEARCH_LIMITS.candidatesPerTerm) as Array<{ path: string; hash: string }>;
      capReached = capReached || files.length >= SEARCH_LIMITS.candidatesPerTerm;
      for (const row of files) {
        if (options.kinds !== undefined && options.kinds.length > 0) {
          continue; // a kind filter asks for symbols only
        }
        let c = candidates.get(row.path);
        if (c === undefined) {
          c = {
            type: "file", path: row.path, symbolKey: null, name: null, qualifiedName: null, kind: null, exported: null, startLine: null, endLine: null,
            score: 0, why: [], contentHash: row.hash, extractor: null, extractorVersion: null, matched: new Set()
          };
          candidates.set(row.path, c);
        }
        const stem = (row.path.split("/").pop() ?? "").replace(/\.[^.]+$/, "").toLowerCase();
        bump(c, term, stem === term ? 40 : 12, stem === term ? `file name is "${term}"` : `path contains "${term}"`);
      }
    }
    const ranked = [...candidates.values()];
    for (const c of ranked) {
      if (c.matched.size > 1) {
        c.score += 10 * (c.matched.size - 1);
        c.why.push(`matches ${c.matched.size} of ${terms.length} terms`);
      }
    }
    ranked.sort((a, b) => b.score - a.score || (a.path < b.path ? -1 : a.path > b.path ? 1 : 0) || (a.startLine ?? 0) - (b.startLine ?? 0) || ((a.symbolKey ?? "") < (b.symbolKey ?? "") ? -1 : 1));
    const page = ranked.slice(offset, offset + limit);
    const more = ranked.length > offset + limit && offset + limit <= SEARCH_LIMITS.maxOffset;
    return {
      generationId, terms, offset, queryHash, totalMatches: ranked.length, candidateCapReached: capReached, truncated: ranked.length > offset + limit || capReached,
      hits: page.map(({ matched: _matched, ...hit }) => hit),
      nextCursor: more ? encodeCursor(generationId, queryHash, offset + limit) : null
    };
  })();
}
