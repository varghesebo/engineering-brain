import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import type { Language, Node, Parser } from "web-tree-sitter";
import type {
  AdapterGrammar, DiagnosticFact, ExportFact, ExtractedFact, ImportedName, LanguageAdapter, ParameterFact, RefFact, SymbolFact, SymbolKind, SymbolRefFact, SymbolRelationFact
} from "../extractor.js";

/**
 * TS/JS/TSX/JSX adapter (tree-sitter WASM, spike S1). SYNTAX facts only: declarations, ownership, exports, import
 * specifiers. It never claims what a call or import resolves to; non-literal `import(x)` / `require(x)` targets are
 * recorded as NULL = explicitly unknown.
 *
 * Grammars: `typescript` for .ts/.mts/.cts; `tsx` for .tsx/.jsx and ALSO .js/.mjs/.cjs (JavaScript commonly contains JSX, which
 * the plain TypeScript grammar rejects). Positions: lines are 1-based, columns are UTF-16 code units, byte offsets are UTF-8.
 * Facts contain no literal values (parameter defaults, string contents) beyond import/export specifiers.
 */
const require = createRequire(import.meta.url);

const LIMITS = { symbols: 5000, refs: 5000, exports: 5000, diagnostics: 20, nodes: 600_000, parameters: 40, nameChars: 120, patternNames: 12, relations: 2000, symbolRefs: 5000, refsPerOwner: 40 } as const;

const GRAMMARS: readonly AdapterGrammar[] = [
  { id: "typescript", extensions: [".ts", ".mts", ".cts"] },
  { id: "tsx", extensions: [".tsx", ".jsx", ".js", ".mjs", ".cjs"] }
];

const FUNCTION_VALUES = new Set(["arrow_function", "function_expression", "function", "generator_function"]);
const CLASS_VALUES = new Set(["class", "class_expression"]);
const DECLARATIONS = new Set([
  "function_declaration", "generator_function_declaration", "function_signature", "class_declaration", "abstract_class_declaration",
  "interface_declaration", "type_alias_declaration", "enum_declaration", "internal_module", "module"
]);

/** Parser and grammar versions are part of the extractor version: upgrading either must not reuse facts under the old key. */
function dependencyVersion(resolvePath: string): string {
  try {
    const dir = dirname(resolvePath);
    for (const candidate of [dir, dirname(dir)]) {
      const json = JSON.parse(readFileSync(join(candidate, "package.json"), "utf8")) as { name?: string; version?: string };
      if (json.version !== undefined && json.name !== undefined && resolvePath.includes(json.name)) {
        return json.version;
      }
    }
  } catch {
    // fall through
  }
  return "unknown";
}
const ADAPTER_VERSION = `2+wts${dependencyVersion(require.resolve("web-tree-sitter"))}+tst${dependencyVersion(require.resolve("tree-sitter-typescript/tree-sitter-typescript.wasm"))}`;

type GrammarName = "typescript" | "tsx";
interface Loaded {
  parser: Parser;
  grammars: Record<GrammarName, Language>;
}
let loading: Promise<Loaded> | null = null;
let loaded: Loaded | null = null;

async function load(): Promise<Loaded> {
  const mod = require("web-tree-sitter") as typeof import("web-tree-sitter");
  await mod.Parser.init();
  const typescript = await mod.Language.load(require.resolve("tree-sitter-typescript/tree-sitter-typescript.wasm"));
  const tsx = await mod.Language.load(require.resolve("tree-sitter-typescript/tree-sitter-tsx.wasm"));
  return { parser: new mod.Parser(), grammars: { typescript, tsx } };
}

const namedOf = (node: Node): Node[] => node.namedChildren.filter((child): child is Node => child !== null);
const squash = (text: string, max: number = LIMITS.nameChars): string => text.replace(/\s+/g, " ").trim().slice(0, max);
const hasToken = (node: Node, token: string): boolean => node.children.some((child) => child !== null && child.type === token);

function stringLiteralValue(node: Node | null): string | null {
  if (node === null || (node.type !== "string" && node.type !== "template_string")) {
    return null;
  }
  if (node.type === "template_string" && namedOf(node).some((child) => child.type === "template_substitution")) {
    return null; // interpolated: unknown
  }
  const text = node.text;
  return text.length >= 2 ? text.slice(1, -1) : null;
}

/** Identifiers bound by a destructuring pattern, in source order (never the default-value expressions). */
function patternIdentifiers(pattern: Node, out: string[] = []): string[] {
  if (out.length >= LIMITS.patternNames) {
    return out;
  }
  switch (pattern.type) {
    case "identifier":
    case "shorthand_property_identifier_pattern":
      out.push(pattern.text);
      return out;
    case "pair_pattern": {
      const value = pattern.childForFieldName("value");
      if (value !== null) {
        patternIdentifiers(value, out);
      }
      return out;
    }
    case "object_assignment_pattern":
    case "assignment_pattern": {
      const left = pattern.childForFieldName("left") ?? namedOf(pattern)[0];
      if (left !== undefined && left !== null) {
        patternIdentifiers(left, out);
      }
      return out;
    }
    default:
      for (const child of namedOf(pattern)) {
        patternIdentifiers(child, out);
      }
      return out;
  }
}

/** A stable, literal-free display name for a parameter pattern, e.g. `{a,b}` or `[x,...r]`. */
function patternName(pattern: Node): string {
  if (pattern.type === "identifier" || pattern.type === "this") {
    return squash(pattern.text);
  }
  const names = patternIdentifiers(pattern).join(",");
  if (pattern.type === "object_pattern") {
    return `{${names}}`;
  }
  if (pattern.type === "array_pattern") {
    return `[${names}]`;
  }
  return "<pattern>";
}

function parametersOf(node: Node): ParameterFact[] | null {
  const list = node.childForFieldName("parameters");
  const single = node.childForFieldName("parameter");
  const raw = list !== null ? namedOf(list) : single !== null ? [single] : null;
  if (raw === null) {
    return null;
  }
  return raw.slice(0, LIMITS.parameters).map((param): ParameterFact => {
    const pattern = param.childForFieldName("pattern") ?? param.childForFieldName("left") ?? param;
    const rest = pattern.type === "rest_pattern" || param.type === "rest_pattern";
    const bound = rest ? namedOf(pattern.type === "rest_pattern" ? pattern : param)[0] ?? pattern : pattern;
    return {
      name: patternName(bound),
      optional: param.type === "optional_parameter",
      rest,
      hasDefault: param.childForFieldName("value") !== null || param.childForFieldName("right") !== null || pattern.type === "assignment_pattern" || param.type === "assignment_pattern"
    };
  });
}

/** Identifiers declared by a function's parameter list. */
function parameterIdentifiers(node: Node): Set<string> {
  const names = new Set<string>();
  const list = node.childForFieldName("parameters");
  const single = node.childForFieldName("parameter");
  for (const param of list !== null ? namedOf(list) : single !== null ? [single] : []) {
    const pattern = param.childForFieldName("pattern") ?? param.childForFieldName("left") ?? param;
    for (const name of patternIdentifiers(pattern.type === "rest_pattern" ? namedOf(pattern)[0] ?? pattern : pattern)) {
      names.add(name);
    }
  }
  return names;
}

const FUNCTION_SCOPES = new Set(["arrow_function", "function_expression", "function", "function_declaration", "generator_function", "generator_function_declaration", "method_definition"]);
const DECLARING_STATEMENTS = new Set(["lexical_declaration", "variable_declaration"]);

/** Names a block (or `for` head) declares directly: let/const/var declarators and function/class declarations. */
function blockDeclarations(statements: readonly Node[], names: Set<string>): void {
  for (const statement of statements) {
    if (DECLARING_STATEMENTS.has(statement.type)) {
      for (const declarator of namedOf(statement)) {
        const target = declarator.childForFieldName("name");
        if (target !== null) {
          for (const name of patternIdentifiers(target)) {
            names.add(name);
          }
        }
      }
    } else if (statement.type === "function_declaration" || statement.type === "generator_function_declaration" || statement.type === "class_declaration" || statement.type === "abstract_class_declaration") {
      const name = statement.childForFieldName("name");
      if (name !== null) {
        names.add(name.text);
      }
    }
  }
}

/** The names a scope-creating node binds for its own body, or null when the node is not a scope. */
function scopeBindings(node: Node): Set<string> | null {
  const names = new Set<string>();
  if (FUNCTION_SCOPES.has(node.type)) {
    for (const name of parameterIdentifiers(node)) {
      names.add(name);
    }
    const own = node.type === "function_expression" || node.type === "function" || node.type === "generator_function" ? node.childForFieldName("name") : null;
    if (own !== null) {
      names.add(own.text);
    }
    return names;
  }
  switch (node.type) {
    case "statement_block":
      blockDeclarations(namedOf(node), names);
      return names;
    case "catch_clause": {
      const parameter = node.childForFieldName("parameter") ?? namedOf(node).find((n) => n.type !== "statement_block");
      if (parameter !== undefined) {
        for (const name of patternIdentifiers(parameter)) {
          names.add(name);
        }
      }
      return names;
    }
    case "for_in_statement": {
      const left = node.childForFieldName("left");
      if (left !== null) {
        for (const name of patternIdentifiers(left)) {
          names.add(name);
        }
      }
      return names;
    }
    case "for_statement": {
      const init = node.childForFieldName("initializer");
      if (init !== null) {
        blockDeclarations([init], names);
      }
      return names;
    }
    default:
      return null;
  }
}

function fingerprintOf(node: Node): string {
  const params = node.childForFieldName("parameters") ?? node.childForFieldName("parameter");
  const returns = node.childForFieldName("return_type");
  const text = `${params === null ? "" : squash(params.text, 2000)}|${returns === null ? "" : squash(returns.text, 2000)}`;
  return createHash("sha256").update(text).digest("hex").slice(0, 16);
}

interface Draft extends Omit<SymbolFact, "startByte" | "endByte" | "symbolKey"> {
  startIndex: number;
  endIndex: number;
  /** Names this function declares itself (parameters, local variables): a use of such a name is not a use of an import. Not persisted. */
  shadow?: Set<string>;
}

class Collector {
  readonly drafts: Draft[] = [];
  readonly refs: RefFact[] = [];
  readonly exports: ExportFact[] = [];
  readonly relations: SymbolRelationFact[] = [];
  readonly symbolRefs: SymbolRefFact[] = [];
  /** Local names bound by imports/requires of this file: the only names for which identifier references are recorded. */
  readonly importLocals = new Set<string>();
  readonly consumedRequires = new Set<number>();
  private readonly seenRefs = new Set<string>();
  private readonly refsByOwner = new Map<number, number>();
  nodes = 0;
  truncated = false;

  /** Returns the new symbol's index, or null when the symbol limit was reached (callers must not guess an index). */
  symbol(
    kind: SymbolKind, name: string, parentIndex: number | null, node: Node,
    extra: Partial<Pick<Draft, "exported" | "exportName" | "anonymous" | "parameters" | "signatureFingerprint" | "shadow">> = {}
  ): number | null {
    if (this.drafts.length >= LIMITS.symbols) {
      this.truncated = true;
      return null;
    }
    const parent = parentIndex === null ? null : this.drafts[parentIndex] ?? null;
    const qualifiedName = kind === "module" ? "" : parent === null || parent.qualifiedName === "" ? name : `${parent.qualifiedName}.${name}`;
    this.drafts.push({
      kind, name, qualifiedName, parentIndex, startLine: node.startPosition.row + 1, startColumn: node.startPosition.column,
      endLine: node.endPosition.row + 1, endColumn: node.endPosition.column, startIndex: node.startIndex, endIndex: node.endIndex,
      signatureFingerprint: extra.signatureFingerprint ?? null, exported: extra.exported ?? false, exportName: extra.exportName ?? null,
      anonymous: extra.anonymous ?? false, parameters: extra.parameters ?? null, ...(extra.shadow === undefined ? {} : { shadow: extra.shadow })
    });
    return this.drafts.length - 1;
  }

  /** A symbol counts as exported only if every owner up to the module is exported too (a namespace member is not module API otherwise). */
  ownerExported(owner: number): boolean {
    return owner === 0 || this.drafts[owner]?.exported === true;
  }

  ref(kind: RefFact["kind"], target: string | null, names: ImportedName[] | null, line: number): void {
    if (this.refs.length < LIMITS.refs) {
      this.refs.push({ kind, target, names, line });
    } else {
      this.truncated = true;
    }
  }

  /** A local variable of a function: later uses of that name inside it are not uses of an import. */
  declareLocal(owner: number, name: string): void {
    const draft = this.drafts[owner];
    if (draft !== undefined && owner !== 0) {
      (draft.shadow ??= new Set()).add(name);
    }
  }

  private readonly scopeCache = new Map<number, Set<string> | null>();

  /** True when an enclosing function, block, loop head or catch clause (below the module) declares `name`: the use is not of the import. */
  shadowedAt(node: Node, name: string): boolean {
    for (let at = node.parent; at !== null && at.type !== "program"; at = at.parent) {
      let names = this.scopeCache.get(at.id);
      if (names === undefined) {
        names = scopeBindings(at);
        this.scopeCache.set(at.id, names);
      }
      if (names?.has(name) === true) {
        return true;
      }
    }
    return false;
  }

  relation(fact: SymbolRelationFact): void {
    if (this.relations.length < LIMITS.relations) {
      this.relations.push(fact);
    } else {
      this.truncated = true;
    }
  }

  symbolRef(symbolIndex: number, name: string, line: number): void {
    const key = `${symbolIndex}\0${name}`;
    if (this.seenRefs.has(key)) {
      return;
    }
    for (let at: number | null = symbolIndex; at !== null; at = this.drafts[at]?.parentIndex ?? null) {
      if (this.drafts[at]?.shadow?.has(name) === true) {
        return; // declared by an enclosing function (parameter or local): not a use of the import
      }
    }
    const count = this.refsByOwner.get(symbolIndex) ?? 0;
    if (count >= LIMITS.refsPerOwner || this.symbolRefs.length >= LIMITS.symbolRefs) {
      this.truncated = true;
      return;
    }
    this.seenRefs.add(key);
    this.refsByOwner.set(symbolIndex, count + 1);
    this.symbolRefs.push({ symbolIndex, name, line });
  }

  export(fact: ExportFact): void {
    if (this.exports.length < LIMITS.exports) {
      this.exports.push(fact);
    } else {
      this.truncated = true;
    }
  }
}

interface Frame {
  node: Node;
  owner: number;
  exported: boolean;
  defaultExport: boolean;
  container: "class" | "interface" | null;
}

const child = (node: Node, owner: number, container: Frame["container"] = null): Frame => ({ node, owner, exported: false, defaultExport: false, container });

function importNames(statement: Node): ImportedName[] {
  const names: ImportedName[] = [];
  const clause = namedOf(statement).find((c) => c.type === "import_clause");
  if (clause === undefined) {
    return names;
  }
  for (const part of namedOf(clause)) {
    if (part.type === "identifier") {
      names.push({ imported: "default", local: part.text });
    } else if (part.type === "namespace_import") {
      names.push({ imported: "*", local: namedOf(part)[0]?.text ?? "*" });
    } else if (part.type === "named_imports") {
      for (const spec of namedOf(part)) {
        const imported = spec.childForFieldName("name") ?? namedOf(spec)[0];
        const alias = spec.childForFieldName("alias");
        if (imported !== null && imported !== undefined) {
          names.push({ imported: imported.text, local: (alias ?? imported).text });
        }
      }
    }
  }
  return names;
}

const DOTTED_NAME = /^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)*$/;

/** The name a heritage clause refers to, as written: `Base`, `ns.Base`; NULL for any other expression (mixins, calls). */
function heritageTarget(node: Node | undefined): string | null {
  if (node === undefined) {
    return null;
  }
  switch (node.type) {
    case "identifier":
    case "type_identifier":
      return node.text;
    case "nested_type_identifier":
    case "member_expression": {
      const text = node.text.replace(/\s+/g, "");
      return DOTTED_NAME.test(text) ? text : null;
    }
    case "generic_type":
      return heritageTarget(namedOf(node)[0]);
    default:
      return null;
  }
}

function collectHeritage(node: Node, symbolIndex: number, c: Collector): void {
  const line = node.startPosition.row + 1;
  // a heritage name declared by an enclosing scope is a local binding, not the import of the same name: leave the target unknown
  const target = (member: Node | undefined): string | null => {
    const name = heritageTarget(member);
    return name !== null && c.shadowedAt(node, name.split(".")[0]!) ? null : name;
  };
  for (const part of namedOf(node)) {
    if (part.type === "class_heritage") {
      for (const clause of namedOf(part)) {
        const members = namedOf(clause).filter((n) => n.type !== "type_arguments");
        if (clause.type === "extends_clause") {
          c.relation({ symbolIndex, relation: "extends", target: target(members[0]), line });
        } else if (clause.type === "implements_clause") {
          for (const member of members) {
            c.relation({ symbolIndex, relation: "implements", target: target(member), line });
          }
        }
      }
    } else if (part.type === "extends_type_clause") {
      for (const member of namedOf(part).filter((n) => n.type !== "type_arguments")) {
        c.relation({ symbolIndex, relation: "extends", target: target(member), line });
      }
    }
  }
}

/** `const x = require("y")` / `const { a, b: c } = require("y")`: the literal target and the local names it binds. */
function requireBinding(declarator: Node): { call: Node; target: string | null; names: ImportedName[] } | null {
  const value = declarator.childForFieldName("value");
  if (value === null || value.type !== "call_expression") {
    return null;
  }
  const fn = value.childForFieldName("function");
  const args = value.childForFieldName("arguments");
  if (fn === null || fn.type !== "identifier" || fn.text !== "require" || args === null) {
    return null;
  }
  const target = stringLiteralValue(namedOf(args)[0] ?? null);
  const pattern = declarator.childForFieldName("name");
  const names: ImportedName[] = [];
  if (pattern !== null && pattern.type === "identifier") {
    names.push({ imported: "*", local: pattern.text });
  } else if (pattern !== null && pattern.type === "object_pattern") {
    for (const member of namedOf(pattern)) {
      if (member.type === "shorthand_property_identifier_pattern") {
        names.push({ imported: member.text, local: member.text });
      } else if (member.type === "pair_pattern") {
        const key = member.childForFieldName("key");
        const local = member.childForFieldName("value");
        if (key !== null && local !== null && local.type === "identifier") {
          names.push({ imported: squash(key.text), local: local.text });
        }
      } else if (member.type === "object_assignment_pattern") {
        const left = namedOf(member)[0];
        if (left !== undefined) {
          names.push({ imported: left.text, local: left.text });
        }
      }
    }
  }
  return { call: value, target, names };
}

/** Identifier positions that DECLARE a name (parameters, destructuring targets, catch bindings) are not references to an import. */
const BINDING_PARENTS = new Set(["required_parameter", "optional_parameter", "rest_pattern", "array_pattern", "catch_clause", "import_specifier", "export_specifier", "namespace_import", "import_clause"]);

function isBindingSite(node: Node): boolean {
  const parent = node.parent;
  if (parent === null) {
    return false;
  }
  if (BINDING_PARENTS.has(parent.type)) {
    return true;
  }
  if ((parent.type === "variable_declarator" || parent.type === "assignment_pattern" || parent.type === "object_assignment_pattern") && (parent.childForFieldName("name") ?? parent.childForFieldName("left"))?.id === node.id) {
    return true;
  }
  return false;
}

function handleImportStatement(node: Node, c: Collector): void {
  const line = node.startPosition.row + 1;
  const requireClause = namedOf(node).find((n) => n.type === "import_require_clause");
  if (requireClause !== undefined) {
    // `import x = require("y")` is a CommonJS-style require with a literal target
    const parts = namedOf(requireClause);
    const local = parts.find((n) => n.type === "identifier");
    c.ref("require", stringLiteralValue(parts.find((n) => n.type === "string") ?? null), [{ imported: "=", local: local?.text ?? "" }], line);
    if (local !== undefined) {
      c.importLocals.add(local.text);
    }
    return;
  }
  const names = importNames(node);
  for (const name of names) {
    c.importLocals.add(name.local);
  }
  c.ref("import", stringLiteralValue(node.childForFieldName("source")), names, line);
}

function handleExportStatement(node: Node, frame: Frame, c: Collector, push: (f: Frame) => void): void {
  const line = node.startPosition.row + 1;
  const source = node.childForFieldName("source");
  const target = stringLiteralValue(source);
  const children = namedOf(node);
  const clause = children.find((n) => n.type === "export_clause");
  const namespace = children.find((n) => n.type === "namespace_export");
  const isDefault = hasToken(node, "default");
  const moduleLevel = frame.owner === 0;

  if (source !== null) {
    if (clause !== undefined) {
      const names: ImportedName[] = [];
      for (const spec of namedOf(clause)) {
        const name = spec.childForFieldName("name") ?? namedOf(spec)[0];
        const alias = spec.childForFieldName("alias");
        if (name === null || name === undefined) {
          continue;
        }
        const exportName = (alias ?? name).text;
        names.push({ imported: name.text, local: exportName });
        c.export({ kind: "reexport", exportName, localName: name.text, symbolIndex: null, source: target, line });
      }
      c.ref("export_from", target, names, line);
    } else if (namespace !== undefined) {
      const exportName = namedOf(namespace)[0]?.text ?? "*";
      c.export({ kind: "reexport_namespace", exportName, localName: null, symbolIndex: null, source: target, line });
      c.ref("export_from", target, [{ imported: "*", local: exportName }], line);
    } else {
      c.export({ kind: "reexport_all", exportName: null, localName: null, symbolIndex: null, source: target, line });
      c.ref("export_from", target, [{ imported: "*", local: "*" }], line);
    }
    return;
  }
  if (clause !== undefined) {
    for (const spec of namedOf(clause)) {
      const name = spec.childForFieldName("name") ?? namedOf(spec)[0];
      const alias = spec.childForFieldName("alias");
      if (name !== null && name !== undefined && moduleLevel) {
        c.export({ kind: "named", exportName: (alias ?? name).text, localName: name.text, symbolIndex: null, source: null, line });
      }
    }
    return;
  }
  const declaration = node.childForFieldName("declaration") ?? node.childForFieldName("value") ?? children[0] ?? null;
  if (declaration === null) {
    return;
  }
  if (hasToken(node, "=")) {
    // TypeScript `export = x` (CommonJS-style single export)
    c.export({ kind: "commonjs", exportName: "export=", localName: declaration.type === "identifier" ? declaration.text : null, symbolIndex: null, source: null, line });
    push(child(declaration, frame.owner));
    return;
  }
  if (declaration.type === "ambient_declaration") {
    for (const inner of namedOf(declaration)) {
      push({ node: inner, owner: frame.owner, exported: true, defaultExport: isDefault, container: null });
    }
    return;
  }
  if (DECLARATIONS.has(declaration.type) || declaration.type === "lexical_declaration" || declaration.type === "variable_declaration") {
    push({ node: declaration, owner: frame.owner, exported: true, defaultExport: isDefault, container: null });
    return;
  }
  if (!isDefault) {
    return;
  }
  if (FUNCTION_VALUES.has(declaration.type) || CLASS_VALUES.has(declaration.type)) {
    const isClass = CLASS_VALUES.has(declaration.type);
    const index = c.symbol(isClass ? "class" : "function", "default", frame.owner, declaration, {
      exported: true, exportName: "default", anonymous: true,
      parameters: isClass ? null : parametersOf(declaration), signatureFingerprint: isClass ? null : fingerprintOf(declaration)
    });
    c.export({ kind: "default", exportName: "default", localName: null, symbolIndex: index, source: null, line });
    push(child(declaration, index ?? frame.owner));
    return;
  }
  c.export({ kind: "default", exportName: "default", localName: declaration.type === "identifier" ? declaration.text : null, symbolIndex: null, source: null, line });
  push(child(declaration, frame.owner));
}

const KIND_BY_TYPE: Record<string, SymbolKind> = {
  function_declaration: "function", generator_function_declaration: "function", function_signature: "function",
  class_declaration: "class", abstract_class_declaration: "class", interface_declaration: "interface",
  type_alias_declaration: "type", enum_declaration: "enum", internal_module: "namespace", module: "namespace"
};

function handleDeclaration(node: Node, frame: Frame, c: Collector, push: (f: Frame) => void): void {
  const nameNode = node.childForFieldName("name");
  const kind = KIND_BY_TYPE[node.type];
  if (kind === undefined || nameNode === null) {
    for (const n of namedOf(node)) {
      push(child(n, frame.owner));
    }
    return;
  }
  const name = squash(nameNode.text);
  const exported = frame.exported && c.ownerExported(frame.owner);
  const exportName = exported ? (frame.defaultExport ? "default" : name) : null;
  const isFunction = kind === "function";
  const index = c.symbol(kind, name, frame.owner, node, {
    exported, exportName, parameters: isFunction ? parametersOf(node) : null, signatureFingerprint: isFunction ? fingerprintOf(node) : null,
    ...(isFunction ? { shadow: parameterIdentifiers(node) } : {})
  });
  if (exported && frame.owner === 0 && index !== null) {
    c.export({ kind: frame.defaultExport ? "default" : "named", exportName, localName: name, symbolIndex: index, source: null, line: node.startPosition.row + 1 });
  }
  if (index !== null && (kind === "class" || kind === "interface")) {
    collectHeritage(node, index, c);
  }
  for (const n of namedOf(node)) {
    // heritage clauses are recorded as relations above, not also as plain references
    if (n.id !== nameNode.id && n.type !== "class_heritage" && n.type !== "extends_type_clause") {
      push(child(n, index ?? frame.owner));
    }
  }
}

function handleVariables(node: Node, frame: Frame, c: Collector, push: (f: Frame) => void): void {
  const topLevel = frame.owner === 0;
  const exported = frame.exported && c.ownerExported(frame.owner);
  for (const declarator of namedOf(node)) {
    if (declarator.type !== "variable_declarator") {
      continue;
    }
    const target = declarator.childForFieldName("name");
    const value = declarator.childForFieldName("value");
    const required = requireBinding(declarator);
    if (required !== null) {
      c.ref("require", required.target, required.names, declarator.startPosition.row + 1);
      c.consumedRequires.add(required.call.id);
      for (const name of required.names) {
        c.importLocals.add(name.local);
      }
    }
    if (target !== null && (target.type === "object_pattern" || target.type === "array_pattern")) {
      if (exported && topLevel) {
        for (const bound of patternIdentifiers(target)) {
          c.export({ kind: "named", exportName: bound, localName: bound, symbolIndex: null, source: null, line: declarator.startPosition.row + 1 });
        }
      }
      if (value !== null) {
        push(child(value, frame.owner));
      }
      continue;
    }
    if (target === null || target.type !== "identifier") {
      if (value !== null) {
        push(child(value, frame.owner));
      }
      continue;
    }
    const isFunction = value !== null && FUNCTION_VALUES.has(value.type);
    const isClass = value !== null && CLASS_VALUES.has(value.type);
    if (!topLevel && !isFunction && !isClass) {
      c.declareLocal(frame.owner, target.text);
      if (value !== null) {
        push(child(value, frame.owner));
      }
      continue;
    }
    const name = squash(target.text);
    const kind: SymbolKind = isFunction ? "function" : isClass ? "class" : "variable";
    const exportName = exported ? name : null;
    const index = c.symbol(kind, name, frame.owner, declarator, {
      exported, exportName, parameters: isFunction && value !== null ? parametersOf(value) : null,
      signatureFingerprint: isFunction && value !== null ? fingerprintOf(value) : null,
      ...(isFunction && value !== null ? { shadow: parameterIdentifiers(value) } : {})
    });
    if (exported && topLevel && index !== null) {
      c.export({ kind: "named", exportName, localName: name, symbolIndex: index, source: null, line: declarator.startPosition.row + 1 });
    }
    if (value !== null) {
      push(child(value, isFunction || isClass ? index ?? frame.owner : frame.owner));
    }
  }
}

function handleMember(node: Node, frame: Frame, c: Collector, push: (f: Frame) => void): boolean {
  const nameNode = node.childForFieldName("name");
  if (nameNode === null) {
    return false;
  }
  const name = nameNode.type === "computed_property_name" ? "[computed]" : squash(nameNode.text);
  if (node.type === "public_field_definition") {
    const value = node.childForFieldName("value");
    if (value === null || !FUNCTION_VALUES.has(value.type)) {
      return false;
    }
    const index = c.symbol("method", name, frame.owner, node, { parameters: parametersOf(value), signatureFingerprint: fingerprintOf(value), shadow: parameterIdentifiers(value) });
    push(child(value, index ?? frame.owner));
    return true;
  }
  const kind: SymbolKind = name === "constructor" && frame.container === "class" ? "constructor" : "method";
  const index = c.symbol(kind, name, frame.owner, node, { parameters: parametersOf(node), signatureFingerprint: fingerprintOf(node), shadow: parameterIdentifiers(node) });
  for (const n of namedOf(node)) {
    if (n.id !== nameNode.id) {
      push(child(n, index ?? frame.owner));
    }
  }
  return true;
}

function handleCommonJs(statement: Node, c: Collector): void {
  const assignment = namedOf(statement)[0];
  if (assignment === undefined || assignment.type !== "assignment_expression") {
    return;
  }
  const left = assignment.childForFieldName("left");
  const right = assignment.childForFieldName("right");
  if (left === null || left.type !== "member_expression") {
    return;
  }
  const line = statement.startPosition.row + 1;
  const text = squash(left.text);
  const localOf = (value: Node | null): string | null => (value !== null && value.type === "identifier" ? value.text : null);
  if (text === "module.exports") {
    if (right !== null && right.type === "object") {
      for (const member of namedOf(right)) {
        if (member.type === "shorthand_property_identifier") {
          c.export({ kind: "commonjs", exportName: member.text, localName: member.text, symbolIndex: null, source: null, line });
        } else if (member.type === "pair") {
          const key = member.childForFieldName("key");
          c.export({ kind: "commonjs", exportName: key === null ? null : squash(key.text), localName: localOf(member.childForFieldName("value")), symbolIndex: null, source: null, line });
        } else if (member.type === "method_definition") {
          c.export({ kind: "commonjs", exportName: member.childForFieldName("name")?.text ?? null, localName: null, symbolIndex: null, source: null, line });
        }
      }
    } else {
      c.export({ kind: "commonjs", exportName: "module.exports", localName: localOf(right), symbolIndex: null, source: null, line });
    }
    return;
  }
  const match = /^(?:module\.)?exports\.([A-Za-z_$][\w$]*)$/.exec(text);
  if (match?.[1] !== undefined) {
    c.export({ kind: "commonjs", exportName: match[1], localName: localOf(right), symbolIndex: null, source: null, line });
  }
}

function collect(root: Node): Collector {
  const c = new Collector();
  c.symbol("module", "<module>", null, root);
  // Imports usually precede their uses, but not always: learn the file's import-bound names before walking bodies.
  for (const statement of namedOf(root)) {
    if (statement.type === "import_statement") {
      for (const name of importNames(statement)) {
        c.importLocals.add(name.local);
      }
    } else if (statement.type === "lexical_declaration" || statement.type === "variable_declaration") {
      for (const declarator of namedOf(statement)) {
        for (const name of requireBinding(declarator)?.names ?? []) {
          c.importLocals.add(name.local);
        }
      }
    }
  }
  const stack: Frame[] = [child(root, 0)];
  while (stack.length > 0) {
    const frame = stack.pop()!;
    const { node } = frame;
    c.nodes += 1;
    if (c.nodes > LIMITS.nodes) {
      c.truncated = true;
      break;
    }
    const pending: Frame[] = [];
    const push = (f: Frame): void => void pending.push(f);
    let descend = true;

    switch (node.type) {
      case "export_statement":
        handleExportStatement(node, frame, c, push);
        descend = false;
        break;
      case "import_statement":
        handleImportStatement(node, c);
        descend = false;
        break;
      case "ambient_declaration":
        for (const inner of namedOf(node)) {
          push({ node: inner, owner: frame.owner, exported: frame.exported, defaultExport: frame.defaultExport, container: null });
        }
        descend = false;
        break;
      case "lexical_declaration":
      case "variable_declaration":
        handleVariables(node, frame, c, push);
        descend = false;
        break;
      case "class_body":
        for (const n of namedOf(node)) {
          push(child(n, frame.owner, "class"));
        }
        descend = false;
        break;
      case "interface_body":
      case "object_type":
        // members are symbols only for interface bodies; inline type literals in signatures are not declarations
        if (node.type === "interface_body" || node.parent?.type === "interface_declaration") {
          for (const n of namedOf(node)) {
            push(child(n, frame.owner, "interface"));
          }
          descend = false;
        }
        break;
      case "method_definition":
      case "method_signature":
      case "abstract_method_signature":
      case "public_field_definition":
        if (frame.container !== null && handleMember(node, frame, c, push)) {
          descend = false;
        }
        break;
      case "expression_statement":
        if (frame.owner === 0) {
          handleCommonJs(node, c);
        }
        break;
      case "identifier":
      case "type_identifier":
      case "shorthand_property_identifier":
        if (c.importLocals.has(node.text) && !isBindingSite(node) && !c.shadowedAt(node, node.text)) {
          c.symbolRef(frame.owner, node.text, node.startPosition.row + 1);
        }
        descend = false;
        break;
      case "call_expression": {
        if (c.consumedRequires.has(node.id)) {
          break; // already recorded, with its bound names, by the enclosing declaration
        }
        const fn = node.childForFieldName("function");
        const args = node.childForFieldName("arguments");
        const first = args === null ? null : namedOf(args)[0] ?? null;
        if (fn !== null && fn.type === "import") {
          c.ref("dynamic_import", stringLiteralValue(first), null, node.startPosition.row + 1);
        } else if (fn !== null && fn.type === "identifier" && fn.text === "require" && args !== null) {
          c.ref("require", stringLiteralValue(first), null, node.startPosition.row + 1);
        }
        break;
      }
      default:
        if (DECLARATIONS.has(node.type)) {
          handleDeclaration(node, frame, c, push);
          descend = false;
        }
    }

    if (descend) {
      for (const n of namedOf(node)) {
        pending.push(child(n, frame.owner, node.type === "class_body" ? "class" : null));
      }
    }
    for (let i = pending.length - 1; i >= 0; i -= 1) {
      stack.push(pending[i]!);
    }
  }
  return c;
}

function diagnosticsOf(root: Node): DiagnosticFact[] {
  const out: DiagnosticFact[] = [];
  const stack: Node[] = [root];
  while (stack.length > 0 && out.length < LIMITS.diagnostics) {
    const node = stack.pop()!;
    if (node.type === "ERROR" || node.isMissing) {
      out.push({
        severity: "error", code: node.isMissing ? "syntax_missing" : "syntax_error",
        message: node.isMissing ? `missing ${node.type}` : "syntax error", line: node.startPosition.row + 1, column: node.startPosition.column
      });
      continue;
    }
    for (const n of node.children) {
      if (n !== null && n.hasError) {
        stack.push(n);
      }
    }
  }
  return out.sort((a, b) => a.line - b.line || a.column - b.column);
}

/** Maps UTF-16 string indexes to UTF-8 byte offsets in one pass (tree-sitter indexes this API by UTF-16 unit). */
function byteOffsets(source: string, indexes: readonly number[]): Map<number, number> {
  const unique = [...new Set(indexes)].sort((a, b) => a - b);
  const result = new Map<number, number>();
  let last = 0;
  let bytes = 0;
  for (const index of unique) {
    bytes += Buffer.byteLength(source.slice(last, index), "utf8");
    last = index;
    result.set(index, bytes);
  }
  return result;
}

function finalize(c: Collector, source: string): SymbolFact[] {
  // `export { a }` / `export default a` after the declaration: link the export to the module-level symbol and mark it exported
  const topLevel = new Map<string, number>();
  c.drafts.forEach((d, index) => {
    if (d.parentIndex === 0 && !topLevel.has(d.name)) {
      topLevel.set(d.name, index);
    }
  });
  for (const fact of c.exports) {
    if ((fact.kind === "named" || fact.kind === "default") && fact.symbolIndex === null && fact.localName !== null) {
      const index = topLevel.get(fact.localName);
      const draft = index === undefined ? undefined : c.drafts[index];
      if (index !== undefined && draft !== undefined) {
        fact.symbolIndex = index;
        draft.exported = true;
        draft.exportName ??= fact.exportName;
      }
    }
  }
  const offsets = byteOffsets(source, c.drafts.flatMap((d) => [d.startIndex, d.endIndex]));
  const ordinals = new Map<string, number>();
  return c.drafts.map((d): SymbolFact => {
    const identity = `${d.kind}\0${d.qualifiedName}`;
    const ordinal = ordinals.get(identity) ?? 0;
    ordinals.set(identity, ordinal + 1);
    const { startIndex, endIndex, shadow: _shadow, ...rest } = d;
    return {
      ...rest, startByte: offsets.get(startIndex) ?? 0, endByte: offsets.get(endIndex) ?? 0,
      symbolKey: createHash("sha256").update(`${identity}\0${ordinal}`).digest("hex").slice(0, 16)
    };
  });
}

export const typescriptAdapter: LanguageAdapter = {
  id: "ts-wasm",
  version: ADAPTER_VERSION,
  grammars: GRAMMARS,
  async prepare(): Promise<void> {
    if (loaded === null) {
      loading ??= load();
      loaded = await loading;
    }
  },
  extract(source, grammarId): ExtractedFact {
    if (loaded === null) {
      throw new Error("typescript adapter used before prepare()");
    }
    const grammar = loaded.grammars[grammarId as GrammarName];
    if (grammar === undefined) {
      throw new Error(`unknown grammar ${grammarId}`);
    }
    loaded.parser.setLanguage(grammar);
    const tree = loaded.parser.parse(source);
    if (tree === null) {
      return { language: null, parseStatus: "error", attrs: { reason: "parse_failed" }, diagnostics: [{ severity: "error", code: "parse_failed", message: "parser returned no tree", line: 1, column: 0 }] };
    }
    try {
      const collected = collect(tree.rootNode);
      const symbols = finalize(collected, source);
      const hasError = tree.rootNode.hasError;
      const diagnostics = hasError ? diagnosticsOf(tree.rootNode) : [];
      if (collected.truncated) {
        diagnostics.push({ severity: "warning", code: "limits_exceeded", message: "extraction limits reached; facts are partial", line: 1, column: 0 });
      }
      return {
        language: null,
        parseStatus: hasError || collected.truncated ? "error" : "ok",
        attrs: { symbolCount: symbols.length, refCount: collected.refs.length, exportCount: collected.exports.length, hasError, truncated: collected.truncated },
        symbols, refs: collected.refs, exports: collected.exports, relations: collected.relations, symbolRefs: collected.symbolRefs, diagnostics
      };
    } finally {
      tree.delete();
    }
  }
};
