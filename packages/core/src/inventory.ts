import { extname } from "node:path";

export interface ExtractedFact {
  language: string | null;
  parseStatus: "ok" | "error" | "skipped";
  attrs: Record<string, string | number | boolean | null>;
}

export interface Extractor {
  id: string;
  /** Bump when output changes; facts are keyed by (content hash, id, version) so old facts are never mixed in. */
  version: string;
  extract(input: { path: string; data: Buffer }): ExtractedFact;
}

const LANGUAGE_BY_EXTENSION: Record<string, string> = {
  ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
  ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
  ".json": "json", ".md": "markdown", ".py": "python", ".java": "java", ".go": "go", ".rs": "rust",
  ".css": "css", ".scss": "scss", ".html": "html", ".yml": "yaml", ".yaml": "yaml", ".sql": "sql", ".sh": "shell"
};

function countLines(data: Buffer): number {
  if (data.length === 0) {
    return 0;
  }
  let lines = 1;
  for (const byte of data) {
    if (byte === 0x0a) {
      lines += 1;
    }
  }
  return data[data.length - 1] === 0x0a ? lines - 1 : lines;
}

/**
 * Foundation placeholder extractor: records language and size facts only (no parsing, no symbols).
 * It exists so generations, content-addressed reuse and incremental behaviour can be built and tested now;
 * the Code Intelligence stage adds real extractors under the same content-hash keying.
 */
export const inventoryExtractor: Extractor = {
  id: "inventory",
  version: "1",
  extract({ path, data }) {
    return {
      language: LANGUAGE_BY_EXTENSION[extname(path).toLowerCase()] ?? null,
      parseStatus: "ok",
      attrs: { byteSize: data.length, lineCount: countLines(data) }
    };
  }
};
