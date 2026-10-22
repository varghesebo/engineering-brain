import { parseArgs } from "node:util";
import { EngbrainError } from "@engbrain/core";
import { GitError } from "@engbrain/security";
import { agentsCommand } from "./commands/agents.js";
import { contextCommand } from "./commands/context.js";
import { mcpCommand } from "./commands/mcp.js";
import { changesCommand, historyCommand, refreshCommand } from "./commands/refresh.js";
import { featureCommand, FEATURE_ACTIONS, type FeatureAction } from "./commands/feature.js";
import { evidenceCommand } from "./commands/evidence.js";
import { sentinelCommand } from "./commands/sentinel.js";
import { memoryCommand, type MemoryGroup } from "./commands/memory.js";
import { gcCommand } from "./commands/gc.js";
import { graphCommand, GRAPH_ACTIONS, type GraphAction } from "./commands/graph.js";
import { importsCommand } from "./commands/imports.js";
import { indexCheckCommand, indexCommand } from "./commands/index.js";
import { initCommand } from "./commands/init.js";
import { statusCommand } from "./commands/status.js";
import { symbolsCommand } from "./commands/symbols.js";
import { uninstallCommand } from "./commands/uninstall.js";
import { resolveContext } from "./context.js";
import { EXIT, type Io } from "./output.js";
import { VERSION } from "./version.js";

export { VERSION };

const HELP = `engbrain ${VERSION} - local, offline-by-default repository intelligence (Foundation stage)

Usage: engbrain <command> [options]

Commands:
  init        create the local store (.engineering-brain/) for this repository
  index       build and atomically publish a new index generation (--stats for detail, --check to verify it is current)
  graph       query the persisted code graph: stats | dependencies | dependents | references | path | impact | cycles | validate
  refresh     ingest new commits into the history ledger and publish the current state (--history=backfill, --max-commits <n>, --status)
  history     commits since a ref in the ledger (--since <ref>|last-refresh [--limit <n>])
  changes     recorded changes of one ingested commit (--commit <sha>)
  feature     the feature graph: list | show <id> | trace <entity> | impact --file|--symbol | provenance <id> | gaps | claims | propose | approve | rebind | retire | validate
  memory      temporal evidence-backed memory: search | show | stale | summary | add | approve | verify | reject | env | operator | gc | export
  bugs        bugs related --file|--symbol|--feature (with fixes and their verification standing)
  decisions   decisions related --file|--symbol|--feature (decisions and rejected approaches)
  evidence    import | list | show <id> | accept <id> | reject <id> | verifier add <id> | status | provenance <memory id>  (imported CI/test evidence is quarantined until signed or accepted)
  impact      potential impact of changed files: impact <files...> | --since <commit>
  tests       advisory test selection: tests select <files...> [--since <commit>] [--sample <n>]
  handoff     session handoff packets: create | show <id> | list | close <id>
  sentinel    task planning and reports (never writes source, never runs repository code): plan | list | status <id> | report <id> | approve <id> | authorize <id> | revalidate <id> | check-scope <id> | verify <id> --dry-run|--explain | import <id> | trace <id> | capability issue <id> | cancel <id>
  context     ranked, token-bounded code context for a task: context "<task>" [--max-tokens <n>]
  mcp         serve the read-only MCP interface on stdio for this repository (--fail-on-stale to refuse stale answers)
  agents      show (or with --apply claude|codex write) the MCP configuration for a coding agent
  symbols     list indexed symbols (--file <path> | --search <text> [--kind <kind>] [--exported] [--limit <n>])
  imports     list module relationships (--file <path> for what it imports, --to <path> for who imports it)
  status      show identity, freshness, parser coverage and the current generation (--check verifies integrity by content hash)
  gc          remove old generations and unreferenced facts
  uninstall   remove generated integration blocks (--purge --yes also deletes the store)

Options:
  --root <dir>   repository directory (default: current directory)
  --json         machine-readable output (all commands)
  -h, --help     show help        --version   show version

Not available in this build: verify.`;

const NOT_YET = new Set(["verify"]);

const OPTIONS = {
  root: { type: "string" }, json: { type: "boolean" }, help: { type: "boolean", short: "h" }, version: { type: "boolean" },
  check: { type: "boolean" }, purge: { type: "boolean" }, yes: { type: "boolean" }, keep: { type: "string" },
  stats: { type: "boolean" }, file: { type: "string" }, to: { type: "string" }, search: { type: "string" }, kind: { type: "string" },
  exported: { type: "boolean" }, limit: { type: "string" }, resolution: { type: "string" },
  symbol: { type: "string" }, package: { type: "string" }, external: { type: "string" }, from: { type: "string" },
  depth: { type: "string" }, mode: { type: "string" }, kinds: { type: "string" },
  "max-tokens": { type: "string" }, "fail-on-stale": { type: "boolean" }, apply: { type: "string" },
  direction: { type: "string" }, by: { type: "string" }, reason: { type: "string" }, "from-file": { type: "string" }, source: { type: "string" }, "source-detail": { type: "string" },
  roles: { type: "string" }, "include-candidates": { type: "boolean" }, "include-stale": { type: "boolean" }, "as-of-valid": { type: "string" }, "as-of-recorded": { type: "string" }, out: { type: "string" }, feature: { type: "string" }, record: { type: "boolean" },
  history: { type: "string" }, since: { type: "string" }, commit: { type: "string" }, "max-commits": { type: "string" }, "time-budget-ms": { type: "string" }, status: { type: "boolean" },
  format: { type: "string" }, revision: { type: "string" }, tree: { type: "string" }, "run-command": { type: "string" }, env: { type: "string", multiple: true }, verifier: { type: "string" }, signature: { type: "string" },
  sample: { type: "string" }, task: { type: "string" }, scope: { type: "string", multiple: true }, ref: { type: "string", multiple: true }, hypothesis: { type: "string", multiple: true }, blocker: { type: "string", multiple: true },
  pending: { type: "string", multiple: true }, "ttl-hours": { type: "string" }, title: { type: "string" }, profile: { type: "string" }, "dry-run": { type: "boolean" }, role: { type: "string" }, principal: { type: "string" }, minutes: { type: "string" }, runs: { type: "string" }, "check-id": { type: "string" }, import: { type: "string" }, requirement: { type: "string" }, behavior: { type: "string" }, test: { type: "string" }, "test-name": { type: "string" }, run: { type: "boolean" }, explain: { type: "boolean" }, path: { type: "string" }, resolve: { type: "string" }, disposition: { type: "string" }, declared: { type: "string", multiple: true }, severity: { type: "string" }, repro: { type: "string" },
  "evidence-seq": { type: "string" }, "evidence-check": { type: "string" }, "evidence-file": { type: "string" }, "evidence-line": { type: "string" }, sha: { type: "string" }, key: { type: "string" }, tokens: { type: "string" }, cost: { type: "string" },
  elapsed: { type: "string" }, failure: { type: "string" }, "max-iterations": { type: "string" }, handoff: { type: "string" }
} as const;

const num = (v: string | undefined): number | undefined => (v === undefined ? undefined : Number(v));
const SYMBOL_KINDS = new Set(["module", "namespace", "function", "class", "constructor", "method", "interface", "type", "enum", "variable"]);
const RESOLUTIONS = new Set(["resolved", "external", "unresolved", "ambiguous", "dynamic"]);
const GRAPH_MODES = new Set(["module", "symbol", "all"]);
const EDGE_KINDS = new Set(["IMPORTS", "RE_EXPORTS", "REFERENCES", "EXTENDS", "IMPLEMENTS", "DEPENDS_ON"]);
/** Named by the design but not served as graph edges in this build: containment and exports are read with `symbols`/`imports`; calls are never produced. */
const UNSERVED_EDGE_KINDS = new Set(["CONTAINS", "DEFINES", "EXPORTS", "CALLS"]);

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
  if (values.run === true && command !== "sentinel") {
    io.stderr(`error: Unknown option '--run' for '${command}': only \`sentinel verify <id> --run\` accepts it (and it refuses unless the OS can enforce every limit)\n`);
    return EXIT.usage;
  }
  const json = values.json === true;
  const keep = values.keep === undefined ? null : Number(values.keep);
  if (keep !== null && (!Number.isInteger(keep) || keep < 1 || keep > 20)) {
    io.stderr("error: --keep must be an integer between 1 and 20\n");
    return EXIT.usage;
  }
  const limit = values.limit === undefined ? undefined : Number(values.limit);
  if (limit !== undefined && (!Number.isInteger(limit) || limit < 1 || limit > 5000)) {
    io.stderr("error: --limit must be an integer between 1 and 5000\n");
    return EXIT.usage;
  }
  if (command !== "feature" && command !== "memory" && values.kind !== undefined && !SYMBOL_KINDS.has(values.kind)) {
    io.stderr(`error: --kind must be one of ${[...SYMBOL_KINDS].join(", ")}\n`);
    return EXIT.usage;
  }
  const depth = values.depth === undefined ? undefined : Number(values.depth);
  if (depth !== undefined && (!Number.isInteger(depth) || depth < 1 || depth > 25)) {
    io.stderr("error: --depth must be an integer between 1 and 25\n");
    return EXIT.usage;
  }
  if (values.mode !== undefined && !GRAPH_MODES.has(values.mode)) {
    io.stderr(`error: --mode must be one of ${[...GRAPH_MODES].join(", ")}\n`);
    return EXIT.usage;
  }
  const kinds = values.kinds === undefined ? undefined : values.kinds.split(",").map((k) => k.trim().toUpperCase());
  const unserved = kinds?.filter((k) => UNSERVED_EDGE_KINDS.has(k)) ?? [];
  if (unserved.length > 0) {
    io.stderr(`error: ${unserved.join(", ")} ${unserved.length === 1 ? "is" : "are"} not served as graph edges in this build (use \`symbols\` / \`imports\` for structure; calls are never produced)\n`);
    return EXIT.usage;
  }
  if (kinds !== undefined && kinds.some((k) => !EDGE_KINDS.has(k))) {
    io.stderr(`error: --kinds must be a comma list of ${[...EDGE_KINDS].join(", ")}\n`);
    return EXIT.usage;
  }
  if (command === "graph" && (positionals[1] === undefined || !GRAPH_ACTIONS.has(positionals[1]))) {
    io.stderr(`error: graph needs one of: ${[...GRAPH_ACTIONS].join(", ")}\n`);
    return EXIT.usage;
  }
  if (values.resolution !== undefined && !RESOLUTIONS.has(values.resolution)) {
    io.stderr(`error: --resolution must be one of ${[...RESOLUTIONS].join(", ")}\n`);
    return EXIT.usage;
  }
  const maxTokens = values["max-tokens"] === undefined ? undefined : Number(values["max-tokens"]);
  if (maxTokens !== undefined && (!Number.isInteger(maxTokens) || maxTokens < 500 || maxTokens > 32000)) {
    io.stderr("error: --max-tokens must be an integer between 500 and 32000\n");
    return EXIT.usage;
  }
  if (command === "context" && (positionals[1] === undefined || positionals[1].trim() === "")) {
    io.stderr('error: context needs a task description, e.g. engbrain context "add retry to the upload client"\n');
    return EXIT.usage;
  }
  const maxCommits = values["max-commits"] === undefined ? undefined : Number(values["max-commits"]);
  if (maxCommits !== undefined && (!Number.isInteger(maxCommits) || maxCommits < 1 || maxCommits > 1_000_000)) {
    io.stderr("error: --max-commits must be an integer between 1 and 1000000\n");
    return EXIT.usage;
  }
  const timeBudget = values["time-budget-ms"] === undefined ? undefined : Number(values["time-budget-ms"]);
  if (timeBudget !== undefined && (!Number.isInteger(timeBudget) || timeBudget < 100)) {
    io.stderr("error: --time-budget-ms must be an integer of at least 100\n");
    return EXIT.usage;
  }
  if (values.history !== undefined && values.history !== "backfill" && values.history !== "none") {
    io.stderr("error: --history must be backfill or none\n");
    return EXIT.usage;
  }
  if (command === "feature" && (positionals[1] === undefined || !FEATURE_ACTIONS.has(positionals[1]))) {
    io.stderr(`error: feature needs one of: ${[...FEATURE_ACTIONS].join(", ")}\n`);
    return EXIT.usage;
  }
  if (command === "changes" && values.commit === undefined) {
    io.stderr("error: changes needs --commit <sha>\n");
    return EXIT.usage;
  }
  if (values.apply !== undefined && values.apply !== "claude" && values.apply !== "codex") {
    io.stderr("error: --apply must be claude or codex\n");
    return EXIT.usage;
  }
  try {
    const context = await resolveContext(values.root ?? io.cwd, io.env);
    try {
      const memoryOptions = {
        positionals: positionals.slice(1), roles: values.roles, fromFile: values["from-file"], reason: values.reason, kind: values.kind, includeCandidates: values["include-candidates"] === true,
        includeStale: values["include-stale"] === true, asOfValid: values["as-of-valid"], asOfRecorded: values["as-of-recorded"], limit, maxTokens, file: values.file, symbol: values.symbol,
        feature: values.feature, out: values.out, record: values.record === true, yes: values.yes === true, failOnStale: values["fail-on-stale"] === true
      };
      switch (command) {
        case "init":
          await initCommand(io, context, json);
          return EXIT.ok;
        case "index":
          if (values.check === true) {
            return await indexCheckCommand(io, context, json);
          }
          await indexCommand(io, context, json, { stats: values.stats === true });
          return EXIT.ok;
        case "symbols":
          await symbolsCommand(io, context, json, {
            file: values.file, search: values.search, kind: values.kind as never, exportedOnly: values.exported === true, limit
          });
          return EXIT.ok;
        case "graph":
          return await graphCommand(io, context, json, positionals[1] as GraphAction, {
            file: values.file, symbol: values.symbol, package: values.package, external: values.external, from: values.from, to: values.to,
            depth, limit, mode: values.mode as never, kinds
          });
        case "imports":
          await importsCommand(io, context, json, { file: values.file, to: values.to, resolution: values.resolution, limit });
          return EXIT.ok;
        case "status":
          return await statusCommand(io, context, json, values.check === true);
        case "feature":
          return await featureCommand(io, context, json, positionals[1] as FeatureAction, {
            arg: positionals.slice(2).join(" ") || undefined, search: values.search, file: values.file, symbol: values.symbol, depth, limit, direction: values.direction, by: values.by,
            reason: values.reason, fromFile: values["from-file"], source: values.source, sourceDetail: values["source-detail"], kind: values.kind, yes: values.yes === true
          });
        case "impact":
        case "tests":
        case "handoff":
        case "evidence":
          if (command === "evidence" && positionals[1] === "provenance") {
            return await memoryCommand(io, context, json, "evidence", memoryOptions);
          }
          return await evidenceCommand(io, context, json, command, {
            positionals: positionals.slice(1), format: values.format, revision: values.revision, tree: values.tree, runCommand: values["run-command"], env: values.env ?? [], verifier: values.verifier,
            signature: values.signature, since: values.since, sample: values.sample === undefined ? undefined : Number(values.sample), file: values.file, task: values.task, scope: values.scope ?? [], refs: values.ref ?? [],
            hypotheses: values.hypothesis ?? [], blockers: values.blocker ?? [], pending: values.pending ?? [], ttlHours: values["ttl-hours"] === undefined ? undefined : Number(values["ttl-hours"]), limit
          });
        case "memory":
        case "bugs":
        case "decisions":
          return await memoryCommand(io, context, json, command as MemoryGroup, memoryOptions);
        case "sentinel":
          return await sentinelCommand(io, context, json, { positionals: positionals.slice(1), title: values.title, scope: values.scope ?? [], profile: values.profile, dryRun: values["dry-run"] === true, reason: values.reason, failOnStale: values["fail-on-stale"] === true, role: values.role, principal: values.principal, minutes: values.minutes === undefined ? undefined : Number(values.minutes), runs: values.runs === undefined ? undefined : Number(values.runs), check: values["check-id"], importId: values.import, requirement: values.requirement === undefined ? undefined : Number(values.requirement), behavior: values.behavior, test: values.test, testName: values["test-name"], run: values.run === true, explain: values.explain === true, path: values.path, resolve: values.resolve, disposition: values.disposition, declared: values.declared ?? [], severity: values.severity, repro: values.repro,
            evidenceSeq: num(values["evidence-seq"]), evidenceCheck: values["evidence-check"], evidenceFile: values["evidence-file"], evidenceLine: num(values["evidence-line"]), sha: values.sha, key: values.key, tokens: num(values.tokens),
            cost: num(values.cost), elapsed: num(values.elapsed), failure: values.failure, maxIterations: num(values["max-iterations"]), handoffId: values.handoff });
        case "refresh":
          await refreshCommand(io, context, json, { history: (values.history as "backfill" | "none" | undefined) ?? "none", maxCommits, timeBudgetMs: timeBudget, status: values.status === true });
          return EXIT.ok;
        case "history":
          await historyCommand(io, context, json, values.since, limit);
          return EXIT.ok;
        case "changes":
          await changesCommand(io, context, json, values.commit!);
          return EXIT.ok;
        case "context":
          await contextCommand(io, context, json, positionals.slice(1).join(" "), maxTokens);
          return EXIT.ok;
        case "mcp":
          await mcpCommand(io, context, values["fail-on-stale"] === true);
          return EXIT.ok;
        case "agents":
          return await agentsCommand(io, context, json, values.apply as "claude" | "codex" | undefined);
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
