import { findModuleEdges, Store } from "@engbrain/core";
import type { CliContext } from "../context.js";
import { printable, printJsonOrText, type Io } from "../output.js";
import { toRepoPath } from "../paths.js";

export async function importsCommand(
  io: Io, context: CliContext, json: boolean, options: { file: string | undefined; to: string | undefined; resolution: string | undefined; limit: number | undefined }
): Promise<void> {
  const store = await Store.open({ root: context.root, git: context.git, hardenedGit: context.hardenedGit, installId: context.installId });
  try {
    const result = findModuleEdges(store.db, {
      ...(options.file === undefined ? {} : { from: toRepoPath(context.root, io.cwd, options.file) }),
      ...(options.to === undefined ? {} : { to: toRepoPath(context.root, io.cwd, options.to) }),
      ...(options.resolution === undefined ? {} : { resolution: options.resolution }),
      ...(options.limit === undefined ? {} : { limit: options.limit })
    });
    const lines = result.rows.map((e) => {
      const target = e.resolvedPath ?? (e.specifier === null ? "(dynamic, target unknown)" : e.specifier);
      return `${e.from}:${e.line}  ${e.kind.padEnd(14)} ${(e.specifier ?? "<non-literal>").padEnd(28)} -> ${target}  [${e.resolution}: ${e.reason}]`;
    });
    const footer = result.generationId === null ? "no index yet: run `engbrain index`" : `${result.rows.length} relationships from generation ${result.generationId}${result.truncated ? " (truncated; use --limit)" : ""}`;
    printJsonOrText(io, json, { generationId: result.generationId, truncated: result.truncated, edges: result.rows }, lines.map(printable).concat(footer).join("\n"));
  } finally {
    store.close();
  }
}
