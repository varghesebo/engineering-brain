import { findSymbols, Store, type SymbolKind } from "@engbrain/core";
import type { CliContext } from "../context.js";
import { printable, printJsonOrText, type Io } from "../output.js";
import { toRepoPath } from "../paths.js";

export interface SymbolsOptions {
  file: string | undefined;
  search: string | undefined;
  kind: SymbolKind | undefined;
  exportedOnly: boolean;
  limit: number | undefined;
}

export async function symbolsCommand(io: Io, context: CliContext, json: boolean, options: SymbolsOptions): Promise<void> {
  const store = await Store.open({ root: context.root, git: context.git, hardenedGit: context.hardenedGit, installId: context.installId });
  try {
    const result = findSymbols(store.db, {
      ...(options.file === undefined ? {} : { file: toRepoPath(context.root, io.cwd, options.file) }),
      ...(options.search === undefined ? {} : { search: options.search }),
      ...(options.kind === undefined ? {} : { kind: options.kind }),
      exportedOnly: options.exportedOnly,
      ...(options.limit === undefined ? {} : { limit: options.limit })
    });
    const lines = result.rows.map(
      (s) => `${s.path}:${s.startLine}:${s.startColumn + 1}  ${s.kind.padEnd(11)} ${s.qualifiedName}${s.exported ? "  [export" + (s.exportName === null || s.exportName === s.name ? "" : ` as ${s.exportName}`) + "]" : ""}${s.anonymous ? "  (anonymous)" : ""}`
    );
    const footer = result.generationId === null ? "no index yet: run `engbrain index`" : `${result.rows.length} symbols from generation ${result.generationId}${result.truncated ? " (truncated; use --limit)" : ""}`;
    printJsonOrText(io, json, { generationId: result.generationId, truncated: result.truncated, symbols: result.rows }, lines.map(printable).concat(footer).join("\n"));
  } finally {
    store.close();
  }
}
