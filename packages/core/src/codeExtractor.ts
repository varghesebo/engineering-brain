import { typescriptAdapter } from "./adapters/typescript.js";
import type { ExtractedFact, Extractor, LanguageAdapter } from "./extractor.js";

/** Every code extractor id starts with this prefix: `code:<adapter>:<grammar>`. */
export const CODE_EXTRACTOR_PREFIX = "code:";
/** SQL LIKE pattern matching every code extractor id. */
export const CODE_EXTRACTOR_LIKE = "code:%";
export const isCodeExtractorId = (id: string): boolean => id.startsWith(CODE_EXTRACTOR_PREFIX);

/**
 * One extractor PER GRAMMAR of each adapter. Facts are keyed by (content hash, extractor id, version), and which grammar
 * parses a file depends on its extension, so the grammar is part of the extractor identity and `appliesTo` selects it.
 * That way identical bytes at a `.ts` and a `.tsx` path can never share (or poison) each other's facts, and a path no
 * grammar supports gets no fact at all (rather than a cached "skipped" fact that a supported path could later inherit).
 * An exception inside an adapter is contained: that file gets an `error` fact with a generic diagnostic.
 */
export function createCodeExtractors(adapters: readonly LanguageAdapter[]): Extractor[] {
  return adapters.flatMap((adapter) =>
    adapter.grammars.map((grammar): Extractor => {
      return {
        id: `${CODE_EXTRACTOR_PREFIX}${adapter.id}:${grammar.id}`,
        version: adapter.version,
        prepare: () => adapter.prepare(),
        extensions: grammar.extensions,
        extract({ data }): ExtractedFact {
          try {
            return adapter.extract(data.toString("utf8"), grammar.id);
          } catch {
            return {
              language: null, parseStatus: "error", attrs: { reason: "adapter_exception" },
              diagnostics: [{ severity: "error", code: "adapter_exception", message: "language adapter failed on this file", line: 1, column: 0 }]
            };
          }
        }
      };
    })
  );
}

export const DEFAULT_ADAPTERS: readonly LanguageAdapter[] = [typescriptAdapter];
export const codeExtractors: readonly Extractor[] = createCodeExtractors(DEFAULT_ADAPTERS);

/** Extensions any code extractor handles: files outside this set are "unsupported" for code intelligence. */
export function supportedCodeExtensions(adapters: readonly LanguageAdapter[] = DEFAULT_ADAPTERS): Set<string> {
  return new Set(adapters.flatMap((a) => a.grammars.flatMap((g) => g.extensions)));
}
