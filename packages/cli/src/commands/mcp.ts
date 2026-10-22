import { checkFreshness, EngbrainError, Store } from "@engbrain/core";
import type { CliContext } from "../context.js";
import { McpServer } from "../mcp/server.js";
import type { Io } from "../output.js";
import { VERSION } from "../version.js";

/** Runs the read-only MCP server on stdin/stdout, bound to this repository. Nothing but protocol messages is written to stdout. */
export async function mcpCommand(io: Io, context: CliContext, failOnStale: boolean): Promise<void> {
  if (io.stdin === undefined) {
    throw new EngbrainError("INTERNAL", "no input stream is available for the MCP server");
  }
  const store = await Store.openReadOnly({ root: context.root, git: context.git, hardenedGit: context.hardenedGit, installId: context.installId });
  try {
    const server = new McpServer({
      db: store.db, root: context.root, storeDir: store.dir, version: VERSION, failOnStale, write: io.stdout,
      freshness: () => checkFreshness(store, context.git, context.hardenedGit, { verify: false })
    });
    await server.run(io.stdin);
  } finally {
    store.close();
  }
}
