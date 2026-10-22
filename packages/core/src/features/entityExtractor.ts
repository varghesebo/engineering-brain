import type { Extractor } from "../extractor.js";
import { detectFrameworkMarkers, detectOpenApi, detectScript, detectSql } from "./detectors.js";

export const ENTITY_EXTRACTOR_PREFIX = "feature:entities";
export const isEntityExtractorId = (id: string): boolean => id === ENTITY_EXTRACTOR_PREFIX || id.startsWith(`${ENTITY_EXTRACTOR_PREFIX}:`);
/** SQL LIKE pattern matching every entity extractor id. */
export const ENTITY_EXTRACTOR_LIKE = `${ENTITY_EXTRACTOR_PREFIX}:%`;

const SCRIPT_EXTENSIONS = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts"] as const;

/**
 * Deterministic, lexical detection of feature-shaped things (routes, client calls, events, jobs, UI routes, SQL tables and queries, test cases, OpenAPI operations).
 * Content-keyed like every extractor: facts carry no path. ONE EXTRACTOR PER CONTENT CLASS (script, sql, json): the behaviour depends on the class, so the class is part
 * of the extractor id and the same bytes at a `.ts` and a `.sql` path can never share, or poison, each other's facts. It is a lexer-based scan, not a parser.
 */
export const entityExtractors: readonly Extractor[] = [
  { id: `${ENTITY_EXTRACTOR_PREFIX}:script`, version: "2", extensions: SCRIPT_EXTENSIONS, extract: ({ data }) => ({ language: null, parseStatus: "ok", attrs: {}, entities: detectScript(data.toString("utf8")) }) },
  { id: `${ENTITY_EXTRACTOR_PREFIX}:sql`, version: "2", extensions: [".sql"], extract: ({ data }) => ({ language: null, parseStatus: "ok", attrs: {}, entities: detectSql(data.toString("utf8")) }) },
  {
    id: `${ENTITY_EXTRACTOR_PREFIX}:json`, version: "2", extensions: [".json"],
    extract: ({ data }) => {
      const text = data.length <= 2_000_000 ? data.toString("utf8") : "";
      return { language: null, parseStatus: "ok", attrs: {}, entities: [...detectOpenApi(text), ...detectFrameworkMarkers(text)] };
    }
  }
];
