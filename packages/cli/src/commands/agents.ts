import { accessSync, constants, existsSync, readFileSync, realpathSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { delimiter, join } from "node:path";
import { fileURLToPath } from "node:url";
import { EngbrainError } from "@engbrain/core";
import type { CliContext } from "../context.js";
import { EXIT, printable, printJsonOrText, type Io } from "../output.js";

type Agent = "claude" | "codex";

const MARK_BEGIN = "# >>> engbrain (managed block; remove with `engbrain agents` guidance) >>>";
const MARK_END = "# <<< engbrain <<<";

function onPath(binary: string, env: NodeJS.ProcessEnv): boolean {
  return (env["PATH"] ?? "").split(delimiter).some((dir) => {
    try {
      accessSync(join(dir, binary), constants.X_OK);
      return true;
    } catch {
      return false;
    }
  });
}

/** The server command an agent should launch. Absolute paths: no PATH lookup, no shell, no package download. */
function serverCommand(root: string): { command: string; args: string[] } {
  // built layout: dist/commands/agents.js -> dist/bin.js; running from sources (tests): src/commands -> ../../dist/bin.js
  const bin = ["../bin.js", "../../dist/bin.js"].map((p) => fileURLToPath(new URL(p, import.meta.url))).find((p) => existsSync(p));
  if (bin === undefined) {
    throw new EngbrainError("INTERNAL", "cannot locate this installation's bin.js (is the project built?)");
  }
  return { command: process.execPath, args: [bin, "mcp", "--root", root] };
}

const tomlString = (s: string): string => JSON.stringify(s);

function codexBlock(root: string): string {
  const { command, args } = serverCommand(root);
  return `${MARK_BEGIN}\n[mcp_servers.engbrain]\ncommand = ${tomlString(command)}\nargs = [${args.map(tomlString).join(", ")}]\n${MARK_END}\n`;
}

/** Writes beside the real file (a symlinked dotfile is updated through the link, never replaced by a regular file) keeping its permission bits. */
function atomicWrite(requested: string, text: string, verify: (written: string) => void): void {
  const path = existsSync(requested) ? realpathSync(requested) : requested;
  const mode = existsSync(path) ? statSync(path).mode & 0o777 : 0o600;
  const temp = `${path}.engbrain-tmp-${process.pid}`;
  try {
    writeFileSync(temp, text, { flag: "wx", mode });
    verify(readFileSync(temp, "utf8"));
    renameSync(temp, path);
  } catch (error) {
    rmSync(temp, { force: true });
    throw error;
  }
}

interface Plan { agent: Agent; file: string; present: boolean; configured: boolean; diff: string; apply: (() => void) | null; note: string }

function planClaude(root: string): Plan {
  const file = join(root, ".mcp.json");
  const entry = { type: "stdio", ...serverCommand(root) };
  let doc: { mcpServers?: Record<string, unknown> } = {};
  const exists = existsSync(file);
  const plain = (v: unknown): boolean => typeof v === "object" && v !== null && !Array.isArray(v);
  if (exists) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(file, "utf8"));
    } catch {
      return { agent: "claude", file, present: true, configured: false, diff: "", apply: null, note: "existing .mcp.json is not valid JSON: not touched; add the entry by hand" };
    }
    if (!plain(parsed) || ((parsed as { mcpServers?: unknown }).mcpServers !== undefined && !plain((parsed as { mcpServers?: unknown }).mcpServers))) {
      return { agent: "claude", file, present: true, configured: false, diff: "", apply: null, note: "existing .mcp.json is not an object with an object mcpServers: not touched; add the entry by hand" };
    }
    doc = parsed as typeof doc;
  }
  const configured = doc.mcpServers !== undefined && Object.hasOwn(doc.mcpServers, "engbrain");
  const diff = `+ ${file}\n+   "mcpServers": { "engbrain": ${JSON.stringify(entry)} }`;
  return {
    agent: "claude", file, present: exists, configured, diff: configured ? "" : diff,
    note: configured ? "an engbrain entry already exists: left unchanged (never overwritten)" : "adds one server entry; every other setting is preserved. The entry holds absolute paths of THIS machine: do not commit .mcp.json",
    apply: configured ? null : () => {
      const next = { ...doc, mcpServers: { ...(doc.mcpServers ?? {}), engbrain: entry } };
      atomicWrite(file, `${JSON.stringify(next, null, 2)}\n`, (w) => void JSON.parse(w));
    }
  };
}

function planCodex(root: string, env: NodeJS.ProcessEnv): Plan {
  const home = env["HOME"] ?? env["USERPROFILE"] ?? "";
  const file = join(home, ".codex", "config.toml");
  const exists = existsSync(file);
  const text = exists ? readFileSync(file, "utf8") : "";
  // any spelling of an engbrain entry counts (bare/quoted table, dotted key, inline table under [mcp_servers]): never add a second one
  const configured = text.includes(MARK_BEGIN) || /^\s*\[\s*mcp_servers\s*\.\s*["']?engbrain["']?\s*\]/m.test(text) || /^\s*mcp_servers\s*\.\s*["']?engbrain/m.test(text)
    || (/^\s*\[\s*mcp_servers\s*\]/m.test(text) && /^\s*["']?engbrain["']?\s*=/m.test(text)) || /^\s*mcp_servers\s*=.*engbrain/m.test(text);
  const block = codexBlock(root);
  return {
    agent: "codex", file, present: exists, configured, diff: configured ? "" : block.split("\n").filter(Boolean).map((l) => `+ ${l}`).join("\n"),
    note: configured ? "an engbrain entry already exists: left unchanged (never overwritten)"
      : existsSync(join(home, ".codex")) ? "appends one marked block; existing content is untouched" : "no ~/.codex directory: Codex is not set up here, so nothing is created",
    apply: configured || home === "" || !existsSync(join(home, ".codex")) ? null : () => {
      atomicWrite(file, `${text}${text === "" || text.endsWith("\n") ? "" : "\n"}${block}`, (w) => {
        if (!w.startsWith(text) || !w.includes(MARK_END)) {
          throw new EngbrainError("INTEGRITY_FAILED", "verification of the written configuration failed; nothing was changed");
        }
      });
    }
  };
}

/**
 * `engbrain agents` shows the exact change that would register this repository's read-only MCP server with Claude Code (project `.mcp.json`) or
 * Codex (`~/.codex/config.toml`). It writes only with an explicit `--apply <agent>`, never overwrites an existing entry, and never executes the agents:
 * their versions are therefore NOT checked, so review the diff.
 */
export async function agentsCommand(io: Io, context: CliContext, json: boolean, apply: Agent | undefined): Promise<number> {
  const plans = [planClaude(context.root), planCodex(context.root, io.env)];
  const detected = { claude: onPath("claude", io.env), codex: onPath("codex", io.env) };
  if (apply !== undefined) {
    const plan = plans.find((p) => p.agent === apply)!;
    if (plan.apply === null) {
      io.stderr(`nothing applied for ${apply}: ${plan.note}\n`);
      return EXIT.refused;
    }
    plan.apply();
    io.stdout(`${json ? JSON.stringify({ applied: apply, file: plan.file }) : `applied: ${apply} -> ${plan.file}`}\n`);
    return EXIT.ok;
  }
  const lines = plans.flatMap((p) => [
    `${p.agent}: ${detected[p.agent] ? "found on PATH (not executed; version not checked)" : "not found on PATH"}; config ${printable(p.file)} ${p.present ? "exists" : "does not exist"}`,
    `  ${p.note}`, ...(p.diff === "" ? [] : p.diff.split("\n").map((l) => `  ${printable(l)}`)), ""
  ]);
  lines.push("Nothing was changed. To apply one: engbrain agents --apply claude|codex");
  printJsonOrText(io, json, { detected, plans: plans.map(({ agent, file, present, configured, diff, note }) => ({ agent, file, present, configured, diff, note })) }, lines.join("\n"));
  return EXIT.ok;
}
