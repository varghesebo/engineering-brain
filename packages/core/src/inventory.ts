import { extname } from "node:path";
import type { ExtractedFact, Extractor } from "./extractor.js";

const LANGUAGE_BY_EXTENSION: Record<string, string> = {
  ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
  ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
  ".json": "json", ".md": "markdown", ".py": "python", ".java": "java", ".go": "go", ".rs": "rust",
  ".css": "css", ".scss": "scss", ".html": "html", ".yml": "yaml", ".yaml": "yaml", ".sql": "sql", ".sh": "shell"
};

export function languageForPath(path: string): string | null {
  return LANGUAGE_BY_EXTENSION[extname(path).toLowerCase()] ?? null;
}

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
  extract({ data }) {
    return {
      language: null, // path-derived labels are NOT stored in content-keyed facts; see languageForPath()
      parseStatus: "ok",
      attrs: { byteSize: data.length, lineCount: countLines(data) }
    };
  }
};
