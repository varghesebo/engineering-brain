/**
 * Shared extractor and fact types. Facts are CONTENT-DERIVED: they never contain file paths, so identical bytes
 * extracted by the same extractor version share one set of facts. Path-dependent information (where a file lives,
 * what an import specifier resolves to) is stored separately and per generation.
 */
export type SymbolKind = "module" | "namespace" | "function" | "class" | "constructor" | "method" | "interface" | "type" | "enum" | "variable";

export interface ParameterFact {
  name: string;
  optional: boolean;
  rest: boolean;
  hasDefault: boolean;
}

export interface SymbolFact {
  kind: SymbolKind;
  name: string;
  /** Dotted ownership path within the file, e.g. `Service.handle`. Duplicates are told apart by `symbolKey`. */
  qualifiedName: string;
  /** Index into the same fact's symbol list (the module symbol is index 0); null only for the module symbol. */
  parentIndex: number | null;
  startLine: number;
  startColumn: number;
  endLine: number;
  endColumn: number;
  /** UTF-8 byte offsets into the file content. */
  startByte: number;
  endByte: number;
  /** Hash of parameter/return text; equal fingerprints are only a HINT of continuity, never proof. */
  signatureFingerprint: string | null;
  exported: boolean;
  exportName: string | null;
  /** True for `export default function () {}` style declarations that have no name of their own. */
  anonymous: boolean;
  parameters: ParameterFact[] | null;
  /** Deterministic key within this content: hash(kind, qualified name, ordinal among identical ones). Not a cross-version identity. */
  symbolKey: string;
}

export interface ImportedName {
  imported: string;
  local: string;
}

export interface RefFact {
  kind: "import" | "export_from" | "require" | "dynamic_import";
  /** Literal specifier, or NULL when it is not a literal (explicitly unknown). */
  target: string | null;
  names: ImportedName[] | null;
  line: number;
}

export interface ExportFact {
  kind: "named" | "default" | "reexport" | "reexport_all" | "reexport_namespace" | "commonjs";
  exportName: string | null;
  localName: string | null;
  symbolIndex: number | null;
  source: string | null;
  line: number;
}

/** `class A extends B implements I`, `interface K extends L`: the target as written (identifier or dotted name), NULL when it is an expression. */
export interface SymbolRelationFact {
  /** Index into the same fact's symbol list. */
  symbolIndex: number;
  relation: "extends" | "implements";
  target: string | null;
  line: number;
}

/**
 * An identifier inside a symbol's body whose NAME equals a binding introduced by an import/require in the same file. Purely syntactic:
 * scope and shadowing are not analysed, so this is evidence of a possible reference, never of a call target.
 */
export interface SymbolRefFact {
  /** Index into the same fact's symbol list (0 = the module itself). */
  symbolIndex: number;
  name: string;
  line: number;
}

export interface DiagnosticFact {
  severity: "error" | "warning" | "info";
  code: string;
  /** Generic text only: diagnostics never echo source code. */
  message: string;
  line: number;
  column: number;
}

/**
 * A RAW, content-derived detection of something feature-shaped (an HTTP route, a client call, an event producer or consumer, a UI route, a SQL query or table,
 * a job, a test case, a documented API operation). It carries no path: where the file lives, what a prefix resolves to and what it connects to is decided per
 * generation by the feature builder. `dynamic` means the identifying value (a path, an event name) is not a literal: the detection is real but WHAT it targets is unknown.
 */
export interface EntityFact {
  role: string;
  kind: string;
  /** Normalised identity within its kind (`GET /api/users/{}`, an event name, a table name); null when dynamic. */
  key: string | null;
  name: string;
  method: string | null;
  /** The literal as written (a path, an event name, an expression summary), when there is one. */
  target: string | null;
  dynamic: boolean;
  receiver: string | null;
  /** The handler as written: an identifier or `obj.member`; null for an inline function or when there is none. */
  handler: string | null;
  startLine: number;
  endLine: number;
  attrs: Record<string, string | number | boolean | null | string[]> | null;
}

export interface ExtractedFact {
  language: string | null;
  parseStatus: "ok" | "error" | "skipped";
  attrs: Record<string, string | number | boolean | null>;
  symbols?: SymbolFact[];
  refs?: RefFact[];
  exports?: ExportFact[];
  relations?: SymbolRelationFact[];
  symbolRefs?: SymbolRefFact[];
  diagnostics?: DiagnosticFact[];
  entities?: EntityFact[];
}

export interface Extractor {
  id: string;
  /** Bump when output changes; facts are keyed by (content hash, id, version) so old facts are never mixed in. */
  version: string;
  /** Optional one-time async setup (e.g. loading a WASM grammar) before the synchronous `extract` calls. */
  prepare?(): Promise<void>;
  /**
   * Lower-case path suffixes (with the dot) this extractor applies to; omitted = every file. Facts are keyed by CONTENT, so an
   * extractor must not behave differently per path in a way the key cannot see: instead of branching on the path inside `extract`,
   * use one extractor per variant (e.g. per grammar). The list is recorded with each generation so that SQL joins from paths to
   * facts (view `applicable_facts`) apply exactly the same rule, and no fact is stored for paths that do not apply.
   */
  extensions?: readonly string[];
  extract(input: { path: string; data: Buffer }): ExtractedFact;
}

/** Whether an extractor applies to a path: suffix match on the lower-cased path (the same rule the `applicable_facts` view uses). */
export function extractorApplies(extractor: Pick<Extractor, "extensions">, path: string): boolean {
  if (extractor.extensions === undefined) {
    return true;
  }
  const lower = path.toLowerCase();
  return extractor.extensions.some((extension) => lower.endsWith(extension));
}

/**
 * One language implementation behind the generic code extractor. Adding Python, Go, Rust or Java means adding an
 * adapter; nothing else in the pipeline changes. Adapters receive the path only to choose a grammar (e.g. .tsx vs .ts).
 */
export interface AdapterGrammar {
  /** Becomes part of the extractor id, so facts from different grammars never share a key. */
  id: string;
  /** Lower-case extensions including the dot. Each extension belongs to exactly one grammar of an adapter. */
  extensions: readonly string[];
}

export interface LanguageAdapter {
  id: string;
  /** Must change whenever output can change, including when a parser or grammar dependency is upgraded. */
  version: string;
  grammars: readonly AdapterGrammar[];
  prepare(): Promise<void>;
  extract(source: string, grammarId: string): ExtractedFact;
}
