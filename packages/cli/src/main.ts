import { parseArgs } from "node:util";
import { EngbrainError } from "@engbrain/core";
import { GitError } from "@engbrain/security";
import { gcCommand } from "./commands/gc.js";
import { indexCommand } from "./commands/index.js";
import { initCommand } from "./commands/init.js";
import { statusCommand } from "./commands/status.js";
import { uninstallCommand } from "./commands/uninstall.js";
import { resolveContext } from "./context.js";
import { EXIT, type Io } from "./output.js";

export const VERSION = "0.0.0";

const HELP = `engbrain ${VERSION} - local, offline-by-default repository intelligence (Foundation stage)

Usage: engbrain <command> [options]

Commands:
  init        create the local store (.engineering-brain/) for this repository
  index       build and atomically publish a new index generation
  status      show identity and the current generation (--check verifies integrity)
  gc          remove old generations and unreferenced facts
  uninstall   remove generated integration blocks (--purge --yes also deletes the store)

Options:
  --root <dir>   repository directory (default: current directory)
  --json         machine-readable output
  -h, --help     show help        --version   show version

Not available in this build: context, verify, mcp, agents.`;

const NOT_YET = new Set(["context", "verify", "mcp", "agents"]);

const OPTIONS = {
  root: { type: "string" }, json: { type: "boolean" }, help: { type: "boolean", short: "h" }, version: { type: "boolean" },
  check: { type: "boolean" }, purge: { type: "boolean" }, yes: { type: "boolean" }, keep: { type: "string" }
} as const;

export async function main(argv: string[], io: Io): Promise<number> {
  // Commands planned for later stages must say so plainly, whatever options follow them.
  const lenient = parseArgs({ args: argv, allowPositionals: true, strict: false, options: OPTIONS }).positionals[0];
  if (lenient !== undefined && NOT_YET.has(lenient)) {
    io.stderr(`error: '${lenient}' is not available in this build (Foundation stage only). Nothing was executed.\n`);
    return EXIT.usage;
  }
  let parsed;
  try {
    parsed = parseArgs({ args: argv, allowPositionals: true, options: OPTIONS });
  } catch (error) {
    io.stderr(`error: ${error instanceof Error ? error.message : "invalid arguments"}\n\n${HELP}\n`);
    return EXIT.usage;
  }
  const { values, positionals } = parsed;
  const command = positionals[0];
  if (values.version === true) {
    io.stdout(`${VERSION}\n`);
    return EXIT.ok;
  }
  if (values.help === true || command === undefined) {
    io.stdout(`${HELP}\n`);
    return command === undefined && values.help !== true ? EXIT.usage : EXIT.ok;
  }
  const json = values.json === true;
  const keep = values.keep === undefined ? null : Number(values.keep);
  if (keep !== null && (!Number.isInteger(keep) || keep < 1 || keep > 20)) {
    io.stderr("error: --keep must be an integer between 1 and 20\n");
    return EXIT.usage;
  }
  try {
    const context = await resolveContext(values.root ?? io.cwd, io.env);
    try {
      switch (command) {
        case "init":
          await initCommand(io, context, json);
          return EXIT.ok;
        case "index":
          await indexCommand(io, context, json);
          return EXIT.ok;
        case "status":
          return await statusCommand(io, context, json, values.check === true);
        case "gc":
          await gcCommand(io, context, json, keep);
          return EXIT.ok;
        case "uninstall":
          await uninstallCommand(io, context, json, values.purge === true, values.yes === true);
          return EXIT.ok;
        default:
          io.stderr(`error: unknown command '${command}'\n\n${HELP}\n`);
          return EXIT.usage;
      }
    } finally {
      context.dispose();
    }
  } catch (error) {
    return reportError(io, error);
  }
}

function reportError(io: Io, error: unknown): number {
  if (error instanceof EngbrainError) {
    io.stderr(`error [${error.code}]: ${error.message}\n`);
    return error.code === "POLICY_REFUSED" ? EXIT.refused : EXIT.error;
  }
  if (error instanceof GitError) {
    io.stderr(`error [${error.code}]: ${error.message}\n`);
    return EXIT.error;
  }
  io.stderr("error: unexpected failure\n");
  return EXIT.error;
}
