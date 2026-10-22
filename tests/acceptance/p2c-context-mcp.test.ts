import { createHash } from "node:crypto";
import { chmodSync, cpSync, existsSync, mkdirSync, readFileSync, renameSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { join } from "node:path";
import { assembleContext, checkFreshness, estimateJsonTokens, getInstallId, indexRepository, readGitInfo, searchCode, Store } from "@engbrain/core";
import { HardenedGit } from "@engbrain/security";
import { McpServer } from "../../packages/cli/src/mcp/server.js";
import { afterAll, describe, expect, it } from "vitest";
import { cleanupTempDirs, engbrainHome, git, makeGitRepo, openFor, runCli, tempDir } from "../helpers/env.js";
import { McpClient } from "../helpers/mcp-client.js";

afterAll(cleanupTempDirs);

// A five-module synthetic repository: auth -> session -> store, a consumer, and a test that imports auth.
const FIVE_MODULES: Record<string, string> = {
  "src/auth/login.ts": "import { createSession } from \"../session/session\";\nexport function login(user: string, password: string) {\n  return createSession(user);\n}\nexport function logout(user: string) {\n  return user;\n}\n",
  "src/session/session.ts": "import { saveSession } from \"../store/sessionStore\";\nexport function createSession(user: string) {\n  return saveSession({ user });\n}\n",
  "src/store/sessionStore.ts": "export interface SessionRecord { user: string }\nexport function saveSession(record: SessionRecord) {\n  return record;\n}\n",
  "src/web/handler.ts": "import { login } from \"../auth/login\";\nexport function handleLogin(body: { user: string; password: string }) {\n  return login(body.user, body.password);\n}\n",
  "src/auth/login.test.ts": "import { login } from \"./login\";\nexport const smoke = login(\"a\", \"b\");\n",
  "README.md": "# Demo\n"
};

async function indexed(files: Record<string, string>): Promise<{ repo: string; home: string }> {
  const repo = makeGitRepo(files);
  const home = engbrainHome();
  const o = await openFor(repo, home, true);
  try {
    await indexRepository({ store: o.store, git: o.info, hardenedGit: o.git });
  } finally {
    o.close();
  }
  return { repo, home };
}

async function reindex(ctx: { repo: string; home: string }): Promise<void> {
  const o = await openFor(ctx.repo, ctx.home);
  try {
    await indexRepository({ store: o.store, git: o.info, hardenedGit: o.git });
  } finally {
    o.close();
  }
}

const EMPTY_SHA = createHash("sha256").update("").digest("hex"); // a reader may create an empty -wal file; what matters is that it stays empty
const sha = (path: string): string => createHash("sha256").update(readFileSync(path)).digest("hex");

describe("P2C task context", () => {
  it("retrieves the relevant files, dependency paths, tests and exact source positions for a task", async () => {
    const ctx = await indexed(FIVE_MODULES);
    const o = await openFor(ctx.repo, ctx.home);
    try {
      const packet = assembleContext(o.store.db, { task: "change how login creates a session", root: ctx.repo })!;
      const paths = packet.files.map((f) => f.path);
      expect(paths.slice(0, 2)).toContain("src/auth/login.ts"); // keyword ranking: login.ts and session.ts both match the task words
      expect(paths).toContain("src/session/session.ts");
      const login = packet.files.find((f) => f.path === "src/auth/login.ts")!;
      const sym = login.symbols.find((s) => s.name === "login")!;
      expect([sym.startLine, sym.endLine]).toEqual([2, 4]);
      expect(login.excerpt?.available).toBe(true);
      expect(login.excerpt?.text).toContain("export function login");
      expect(packet.related.some((r) => r.role === "dependency" && r.path === "src/session/session.ts" && r.via.resolution === "resolved")).toBe(true);
      expect(packet.related.some((r) => r.role === "dependent" && r.path === "src/web/handler.ts")).toBe(true);
      expect(packet.tests.some((t) => t.path === "src/auth/login.test.ts" && t.basis === "imports_target" && t.certainty === "resolved")).toBe(true);
      expect(packet.snapshot.generationId).toBeGreaterThan(0);
      expect(packet.notice).toMatch(/UNTRUSTED_DATA/);
      expect(login.provenance).toMatchObject({ extractionMethod: "tree_sitter_syntax", semanticCertainty: "syntactic_only" });
    } finally {
      o.close();
    }
  });

  it("holds the token cap for the WHOLE packet, flags truncation, and is deterministic", async () => {
    const files: Record<string, string> = {};
    for (let i = 0; i < 40; i += 1) {
      files[`src/m${i}/payment${i}.ts`] = `export function processPayment${i}(amount: number) {\n  return amount + ${i};\n}\nexport class PaymentHandler${i} {}\n`;
    }
    const ctx = await indexed(files);
    const o = await openFor(ctx.repo, ctx.home);
    try {
      const small = assembleContext(o.store.db, { task: "payment processing handler", root: ctx.repo, maxTokens: 500, header: { freshness: { level: "heuristic" } } })!;
      expect(small.budget.estimatedTokens).toBeLessThanOrEqual(500);
      expect(estimateJsonTokens(small)).toBeLessThanOrEqual(500);
      expect(small.budget.truncated).toBe(true);
      const again = assembleContext(o.store.db, { task: "payment processing handler", root: ctx.repo, maxTokens: 500, header: { freshness: { level: "heuristic" } } })!;
      expect(JSON.stringify(again)).toBe(JSON.stringify(small));
      const big = assembleContext(o.store.db, { task: "payment processing handler", root: ctx.repo, maxTokens: 32000 })!;
      expect(big.budget.estimatedTokens).toBeLessThanOrEqual(32000);
      // adversarial: oversized / repetitive query text stays bounded
      const hostile = assembleContext(o.store.db, { task: "payment ".repeat(100_000), root: ctx.repo })!;
      expect(hostile.task.length).toBeLessThanOrEqual(500);
      expect(hostile.budget.estimatedTokens).toBeLessThanOrEqual(4000);
      expect(searchCode(o.store.db, { query: "%".repeat(10_000) }).hits).toEqual([]);
    } finally {
      o.close();
    }
  });

  it("paginates search deterministically and refuses a cursor from another query or an older generation", async () => {
    const files: Record<string, string> = {};
    for (let i = 0; i < 30; i += 1) {
      files[`src/f${i}.ts`] = `export function widgetFactory${i}() { return ${i}; }\n`;
    }
    const ctx = await indexed(files);
    const o = await openFor(ctx.repo, ctx.home);
    try {
      const first = searchCode(o.store.db, { query: "widgetFactory", limit: 10 });
      const second = searchCode(o.store.db, { query: "widgetFactory", limit: 10, cursor: first.nextCursor });
      const third = searchCode(o.store.db, { query: "widgetFactory", limit: 10, cursor: second.nextCursor });
      const all = [...first.hits, ...second.hits, ...third.hits].map((h) => h.path);
      expect(new Set(all).size).toBe(30);
      expect(third.nextCursor).toBeNull();
      expect(searchCode(o.store.db, { query: "widgetFactory", limit: 10 })).toEqual(first);
      expect(() => searchCode(o.store.db, { query: "different", cursor: first.nextCursor })).toThrow(/different query/);
      expect(() => searchCode(o.store.db, { query: "widgetFactory", cursor: "not-a-cursor" })).toThrow(/invalid cursor/);
      writeFileSync(join(ctx.repo, "src/extra.ts"), "export const extra = 1;\n");
    } finally {
      o.close();
    }
    const stale = await openFor(ctx.repo, ctx.home);
    const cursor = searchCode(stale.store.db, { query: "widgetFactory", limit: 10 }).nextCursor;
    stale.close();
    await reindex(ctx);
    const after = await openFor(ctx.repo, ctx.home);
    try {
      expect(() => searchCode(after.store.db, { query: "widgetFactory", limit: 10, cursor })).toThrow(/expired/);
    } finally {
      after.close();
    }
  });

  it("never exposes secret-bearing files through search, context, excerpts or errors", async () => {
    const secret = `AKIA${"IOSFODNN7EXAMPLE"}`;
    const ctx = await indexed({
      ...FIVE_MODULES,
      "src/leaky/credentials.ts": `export const uniqueLeakyName = "${secret}";\nexport function leakyHelperFunction() { return 1; }\n`,
      ".env": `API_KEY=${secret}\n`
    });
    const client = new McpClient(ctx.repo, ctx.home);
    try {
      await client.initialize();
      const outputs: string[] = [];
      for (const [tool, args] of [
        ["search_code", { query: "uniqueLeakyName leakyHelperFunction credentials" }], ["find_symbol", { name: "leaky" }],
        ["get_feature_context", { task: "leaky credentials helper uniqueLeakyName" }], ["check_freshness", { paths: ["src/leaky/credentials.ts", ".env"] }],
        ["get_relevant_tests", { file: "src/leaky/credentials.ts" }], ["get_dependency_graph", { file: ".env", direction: "forward" }]
      ] as const) {
        const r = await client.tool(tool, args);
        outputs.push(r.raw);
      }
      const joined = outputs.join("\n");
      expect(joined).not.toContain(secret);
      // the server echoes the caller's own query words; what must be absent is anything FROM the excluded files
      for (const fromIndex of [outputs[0]!, outputs[1]!, outputs[2]!]) {
        expect(fromIndex).not.toContain("src/leaky");
        expect(JSON.parse(fromIndex).data.hits ?? JSON.parse(fromIndex).data.symbols ?? JSON.parse(fromIndex).data.packet.files).toEqual([]);
      }
      expect((await client.tool("search_code", { query: "uniqueLeakyName" })).payload.data.hits).toEqual([]);
      expect(client.stderr).not.toContain(secret);
    } finally {
      await client.close();
    }
  });
});

describe("P2C read-only MCP server (real stdio child process)", () => {
  it("speaks the protocol, lists only read tools, and answers every tool with provenance, freshness and generation", async () => {
    const ctx = await indexed(FIVE_MODULES);
    const client = new McpClient(ctx.repo, ctx.home);
    try {
      const init = await client.initialize();
      expect(init.result.protocolVersion).toBe("2025-06-18");
      expect(init.result.serverInfo.name).toBe("engbrain");
      expect((await client.initialize("1999-01-01")).result.protocolVersion).toBe("2025-06-18");
      const list = await client.request("tools/list");
      const names = list.result.tools.map((t: { name: string }) => t.name).sort();
      expect(names).toEqual(["check_freshness", "find_impacted_components", "find_symbol", "get_dependency_graph", "get_feature_context", "get_memory_provenance", "get_relevant_tests", "get_session_handoff", "get_symbol_references", "get_verification_status", "retrieve_architecture_decisions", "retrieve_related_bugs", "search_code", "search_memory"]);
      expect(names.join(" ")).not.toMatch(/write|delete|exec|run|edit|save|remember/);
      expect((await client.request("ping")).result).toEqual({});

      const search = await client.tool("search_code", { query: "login" });
      expect(search.isError).toBe(false);
      expect(search.payload).toMatchObject({ schemaVersion: 1, truncated: false });
      expect(search.payload.generationId).toBeGreaterThan(0);
      expect(search.payload.freshness.level).toBe("heuristic");
      expect(search.payload.sourceFingerprint).toEqual(expect.any(String));
      expect(search.payload.data.hits[0].provenance).toMatchObject({ extractionMethod: "tree_sitter_syntax", semanticCertainty: "syntactic_only" });

      const sym = await client.tool("find_symbol", { name: "login", exported_only: true });
      const login = sym.payload.data.symbols.find((s: { name: string }) => s.name === "login");
      expect(login.range).toMatchObject({ startLine: 2, endLine: 4 });

      const refs = await client.tool("get_symbol_references", { symbol: "src/auth/login.ts#login" });
      expect(refs.payload.data.references.map((r: { from: { path: string } }) => r.from.path)).toContain("src/web/handler.ts");

      const graph = await client.tool("get_dependency_graph", { file: "src/auth/login.ts", direction: "forward", depth: 3 });
      expect(graph.payload.data.nodes.map((n: { path: string }) => n.path)).toEqual(expect.arrayContaining(["src/session/session.ts", "src/store/sessionStore.ts"]));

      const tests = await client.tool("get_relevant_tests", { file: "src/auth/login.ts" });
      expect(tests.payload.data.selected[0]).toMatchObject({ path: "src/auth/login.test.ts", proof: "imports_changed_file", certainty: "resolved" });

      const context = await client.tool("get_feature_context", { task: "login session", max_tokens: 3000 });
      expect(context.payload.data.packet.files.length).toBeGreaterThan(0);
      expect(context.payload.estimatedTokens).toBeLessThanOrEqual(3000); // the caller's max_tokens bounds the whole response

      const fresh = await client.tool("check_freshness", { paths: ["src/auth/login.ts", "nope.ts", "../escape"] });
      expect(fresh.payload.data.files.map((f: { state: string }) => f.state)).toEqual(["unchanged", "not_indexed", "invalid_path"]);

      const verification = (await client.tool("get_verification_status")).payload.data;
      expect(verification).toMatchObject({ usable: [], imports: 0 });
      const missing = await client.tool("get_session_handoff", { id: "ho_none" });
      expect(missing.isError).toBe(true);
      expect(missing.payload.error.code).toBe("not_found");
      const impacted = await client.tool("find_impacted_components", { files: ["src/session/session.ts"] });
      expect(impacted.payload.data.impacted.map((i: { path: string }) => i.path)).toContain("src/auth/login.ts");
      expect(client.stdoutLines.every((l) => l.startsWith("{"))).toBe(true);
    } finally {
      await client.close();
    }
  });

  it("validates arguments, rejects malformed requests, and bounds message size", async () => {
    const ctx = await indexed(FIVE_MODULES);
    const client = new McpClient(ctx.repo, ctx.home);
    try {
      expect((await client.request("tools/list")).error?.code).toBe(-32002); // before initialize
      await client.initialize();
      expect((await client.request("tools/call", { name: "search_code", arguments: {} })).error?.code).toBe(-32602);
      expect((await client.request("tools/call", { name: "search_code", arguments: { query: "x", extra: 1 } })).error?.code).toBe(-32602);
      expect((await client.request("tools/call", { name: "search_code", arguments: { query: "x", limit: 1e9 } })).error?.code).toBe(-32602);
      expect((await client.request("tools/call", { name: "no_such_tool", arguments: {} })).error?.code).toBe(-32602);
      expect((await client.request("resources/list")).error?.code).toBe(-32601);
      const traversal = await client.tool("get_relevant_tests", { file: "../../etc/passwd" });
      expect(traversal.isError).toBe(true);
      expect(traversal.payload.error.code).toBe("invalid_argument");
      const absolute = await client.tool("check_freshness", { paths: ["/etc/passwd"] });
      expect(absolute.payload.data.files[0].state).toBe("invalid_path");
      client.sendRaw("this is not json\n");
      client.sendRaw("[1,2]\n");
      client.sendRaw(`${"x".repeat(1_100_000)}\n`);
      expect((await client.request("ping")).result).toEqual({});
      expect(client.stdoutLines.some((l) => l.includes("-32700"))).toBe(true);
      expect(client.stdoutLines.some((l) => l.includes("message too large"))).toBe(true);
    } finally {
      expect(await client.close()).toBe(0);
    }
  });

  it("is read-only: no repository or store mutation, and the database handle cannot write", async () => {
    const ctx = await indexed(FIVE_MODULES);
    const dbPath = join(ctx.repo, ".engineering-brain", "store.db");
    const walPath = `${dbPath}-wal`;
    const before = { db: sha(dbPath), wal: existsSync(walPath) ? sha(walPath) : EMPTY_SHA, file: sha(join(ctx.repo, "src/auth/login.ts")) };
    const status = git(ctx.repo, ["status", "--porcelain"]);
    const client = new McpClient(ctx.repo, ctx.home);
    try {
      await client.initialize();
      for (const [tool, args] of [["search_code", { query: "login" }], ["get_feature_context", { task: "login" }], ["check_freshness", { paths: ["src/auth/login.ts"] }]] as const) {
        await client.tool(tool, args);
      }
    } finally {
      await client.close();
    }
    expect(git(ctx.repo, ["status", "--porcelain"])).toBe(status);
    expect(sha(join(ctx.repo, "src/auth/login.ts"))).toBe(before.file);
    expect(sha(dbPath)).toBe(before.db);
    expect(existsSync(walPath) ? sha(walPath) : EMPTY_SHA).toBe(before.wal); // a write would land in the WAL, not the main file
    const { Store, getInstallId, readGitInfo } = await import("@engbrain/core");
    const { HardenedGit } = await import("@engbrain/security");
    const hardened = new HardenedGit();
    try {
      const info = await readGitInfo(ctx.repo, hardened, process.env["HOME"]);
      const store = await Store.openReadOnly({ root: ctx.repo, git: info, hardenedGit: hardened, installId: getInstallId({ ...process.env, ENGBRAIN_HOME: ctx.home }) });
      expect(() => store.db.prepare("DELETE FROM generation_files").run()).toThrow(/readonly|read-only|attempt to write/i);
      store.close();
    } finally {
      hardened.dispose();
    }
  });

  it("refuses a copied store (cross-worktree) and a store that needs a migration", async () => {
    const ctx = await indexed(FIVE_MODULES);
    const other = makeGitRepo({ "x.ts": "export const x = 1;\n" });
    cpSync(join(ctx.repo, ".engineering-brain"), join(other, ".engineering-brain"), { recursive: true });
    const client = new McpClient(other, ctx.home);
    const code = await client.exited;
    expect(code).not.toBe(0);
    expect(client.stderr).toMatch(/STORE_ROOT_MISMATCH|different directory/);
    const run = await runCli(other, ["mcp"], ctx.home);
    expect(run.code).toBe(1);
  });

  it("answers from completed generations only while an indexer publishes concurrently", async () => {
    const files: Record<string, string> = {};
    for (let i = 0; i < 300; i += 1) {
      files[`src/mod${i}.ts`] = `export function feature${i}() { return ${i}; }\n`;
    }
    const ctx = await indexed(files);
    const a = new McpClient(ctx.repo, ctx.home);
    const b = new McpClient(ctx.repo, ctx.home);
    try {
      await a.initialize();
      await b.initialize();
      const seen = new Set<number>();
      let publishing = true;
      const writer = (async () => {
        for (let round = 0; round < 3; round += 1) {
          writeFileSync(join(ctx.repo, `src/added${round}.ts`), `export const added${round} = ${round};\n`);
          await reindex(ctx);
        }
        publishing = false;
      })();
      while (publishing) {
        for (const client of [a, b]) {
          const r = await client.tool("search_code", { query: "feature", limit: 5 });
          expect(r.isError).toBe(false);
          seen.add(r.payload.generationId);
          expect(r.payload.data.totalMatches).toBe(300); // never a half-built generation
          // header and data come from ONE snapshot: generation N contains exactly N-1 of the added files (each matches as a file and as a symbol)
          const added = await client.tool("search_code", { query: "added", limit: 1 });
          expect(added.payload.data.totalMatches).toBe(2 * (added.payload.generationId - 1));
        }
      }
      await writer;
      expect(seen.size).toBeGreaterThanOrEqual(2); // the readers really did observe more than one published generation
      const final = await a.tool("search_code", { query: "added" });
      expect(final.payload.data.totalMatches).toBeGreaterThanOrEqual(3);
    } finally {
      await a.close();
      await b.close();
    }
  }, 180_000);

  it("reports stale freshness and, with --fail-on-stale, refuses to answer from a stale index", async () => {
    const ctx = await indexed(FIVE_MODULES);
    writeFileSync(join(ctx.repo, "src/auth/login.ts"), `${FIVE_MODULES["src/auth/login.ts"]}// edited\n`);
    const warn = new McpClient(ctx.repo, ctx.home);
    const strict = new McpClient(ctx.repo, ctx.home, ["--fail-on-stale"]);
    try {
      await warn.initialize();
      await strict.initialize();
      const w = await warn.tool("search_code", { query: "login" });
      expect(w.payload.freshness.level).toBe("stale");
      expect(w.payload.uncertainty.join(" ")).toMatch(/stale/);
      const s = await strict.tool("search_code", { query: "login" });
      expect(s.isError).toBe(true);
      expect(s.payload.error.code).toBe("stale_index");
      const fresh = await strict.tool("check_freshness", { paths: ["src/auth/login.ts"] });
      expect(fresh.payload.data.files[0].state).toBe("changed"); // freshness itself still answers
      const context = await warn.tool("get_feature_context", { task: "login" });
      const excerpt = context.payload.data.packet.files.find((f: { path: string }) => f.path === "src/auth/login.ts").excerpt;
      expect(excerpt.available).toBe(false);
      expect(excerpt.unavailableReason).toBe("file_changed_since_index");
    } finally {
      await warn.close();
      await strict.close();
    }
  });

  it("never reads through a symlink or outside the repository", async () => {
    const outside = tempDir("engbrain-outside-");
    writeFileSync(join(outside, "private.ts"), "export const outsideSecretSymbol = 1;\n");
    const repo = makeGitRepo(FIVE_MODULES);
    symlinkSync(join(outside, "private.ts"), join(repo, "src", "linked.ts"));
    git(repo, ["add", "src/linked.ts"]);
    git(repo, ["commit", "-q", "-m", "link"]);
    const home = engbrainHome();
    const o = await openFor(repo, home, true);
    try {
      await indexRepository({ store: o.store, git: o.info, hardenedGit: o.git });
    } finally {
      o.close();
    }
    const client = new McpClient(repo, home);
    try {
      await client.initialize();
      const r = await client.tool("search_code", { query: "outsideSecretSymbol linked" });
      expect(r.raw).not.toContain("outsideSecretSymbol");
      expect(r.payload.data.hits.some((h: { path: string }) => h.path === "src/linked.ts")).toBe(false);
      const f = await client.tool("check_freshness", { paths: ["src/linked.ts"] });
      expect(f.payload.data.files[0].state).toBe("not_indexed");
    } finally {
      await client.close();
    }
  });
});

describe("P2C CLI: context and agents", () => {
  it("engbrain context prints a bounded packet (text and JSON) and validates its arguments", async () => {
    const ctx = await indexed(FIVE_MODULES);
    const text = await runCli(ctx.repo, ["context", "login", "session"], ctx.home);
    expect(text.code).toBe(0);
    expect(text.stdout).toContain("src/auth/login.ts");
    const json = JSON.parse((await runCli(ctx.repo, ["context", "login", "--json", "--max-tokens", "600"], ctx.home)).stdout);
    expect(json.packet.budget.estimatedTokens).toBeLessThanOrEqual(600);
    expect((await runCli(ctx.repo, ["context"], ctx.home)).code).toBe(2);
    expect((await runCli(ctx.repo, ["context", "x", "--max-tokens", "5"], ctx.home)).code).toBe(2);
    const empty = makeGitRepo({ "a.ts": "export const a = 1;\n" });
    const none = await runCli(empty, ["context", "anything"], ctx.home);
    expect(none.code).not.toBe(0);
  });

  it("engbrain agents shows a diff, writes only on --apply, never overwrites, and preserves other settings", async () => {
    const ctx = await indexed(FIVE_MODULES);
    const fakeHome = tempDir("engbrain-agenthome-");
    const env = { HOME: fakeHome };
    const show = await runCli(ctx.repo, ["agents"], ctx.home, env);
    expect(show.code).toBe(0);
    expect(show.stdout).toMatch(/Nothing was changed/);
    expect(existsSync(join(ctx.repo, ".mcp.json"))).toBe(false);

    writeFileSync(join(ctx.repo, ".mcp.json"), JSON.stringify({ mcpServers: { other: { command: "x" } }, custom: true }));
    const applied = await runCli(ctx.repo, ["agents", "--apply", "claude"], ctx.home, env);
    expect(applied.code).toBe(0);
    const doc = JSON.parse(readFileSync(join(ctx.repo, ".mcp.json"), "utf8"));
    expect(doc.custom).toBe(true);
    expect(doc.mcpServers.other).toEqual({ command: "x" });
    expect(doc.mcpServers.engbrain.args).toContain("mcp");
    const again = await runCli(ctx.repo, ["agents", "--apply", "claude"], ctx.home, env);
    expect(again.code).toBe(3);

    // the written config really launches a working server
    const entry = doc.mcpServers.engbrain as { command: string; args: string[] };
    expect(entry.command).toBe(process.execPath);
    const launched = spawn(entry.command, entry.args, { env: { ...process.env, ENGBRAIN_HOME: ctx.home }, stdio: ["pipe", "pipe", "pipe"] });
    const reply = await new Promise<string>((resolve) => {
      let out = "";
      let err = "";
      launched.stderr.on("data", (c: Buffer) => void (err += c.toString()));
      launched.on("close", () => resolve(out || `EXITED: ${err}`));
      launched.stdout.on("data", (c: Buffer) => { out += c.toString(); if (out.includes("\n")) { resolve(out); } });
      launched.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18" } })}\n`);
    });
    expect(reply.slice(0, 300)).not.toMatch(/^EXITED/);
    expect(JSON.parse(reply).result.serverInfo.name).toBe("engbrain");
    launched.stdin.end();

    writeFileSync(join(ctx.repo, ".mcp.json"), "{ broken");
    expect((await runCli(ctx.repo, ["agents", "--apply", "claude"], ctx.home, env)).code).toBe(3);
    expect(readFileSync(join(ctx.repo, ".mcp.json"), "utf8")).toBe("{ broken");

    const codexDir = join(fakeHome, ".codex");
    expect((await runCli(ctx.repo, ["agents", "--apply", "codex"], ctx.home, env)).code).toBe(3); // no codex config dir: not created implicitly
    const { mkdirSync } = await import("node:fs");
    mkdirSync(codexDir);
    writeFileSync(join(codexDir, "config.toml"), "model = \"x\"\n");
    chmodSync(join(codexDir, "config.toml"), 0o600);
    expect((await runCli(ctx.repo, ["agents", "--apply", "codex"], ctx.home, env)).code).toBe(0);
    const toml = readFileSync(join(codexDir, "config.toml"), "utf8");
    expect(toml.startsWith("model = \"x\"\n")).toBe(true);
    expect(toml).toContain("[mcp_servers.engbrain]");
    expect((await runCli(ctx.repo, ["agents", "--apply", "codex"], ctx.home, env)).code).toBe(3);
  });
});

describe("P2C review regressions", () => {
  async function pageAll(client: McpClient, tool: string, args: Record<string, unknown>, pick: (payload: any) => string[]): Promise<{ seen: string[]; pages: number; trimmedPages: number }> {
    const seen: string[] = [];
    let cursor: string | null = null;
    let pages = 0;
    let trimmedPages = 0;
    do {
      const r = await client.tool(tool, { ...args, ...(cursor === null ? {} : { cursor }) });
      expect(r.isError).toBe(false);
      seen.push(...pick(r.payload));
      cursor = r.payload.nextCursor;
      trimmedPages += r.payload.uncertainty.some((u: string) => /trimmed|truncated/.test(u)) ? 1 : 0;
      pages += 1;
    } while (cursor !== null && pages < 200);
    return { seen, pages, trimmedPages };
  }

  const manyPayments = (): Record<string, string> => {
    const files: Record<string, string> = {};
    for (let i = 0; i < 120; i += 1) {
      files[`src/payments/domain${i}/paymentProcessingService${i}.ts`] = `export function paymentProcessor${i}() { return ${i}; }\n`;
    }
    return files;
  };

  it("paging never skips results when a page is trimmed to its size cap (search_code and get_feature_context)", async () => {
    const ctx = await indexed(manyPayments());
    const client = new McpClient(ctx.repo, ctx.home);
    try {
      await client.initialize();
      const search = await pageAll(client, "search_code", { query: "payment", limit: 50 }, (p) => p.data.hits.map((h: { path: string; type: string }) => `${h.type}:${h.path}`));
      expect(search.trimmedPages).toBeGreaterThan(0); // the cap really did trim a page
      expect(new Set(search.seen).size).toBe(search.seen.length); // no duplicates
      expect(search.seen.filter((x) => x.startsWith("file:")).length).toBe(120);
      expect(search.seen.filter((x) => x.startsWith("symbol:")).length).toBe(120);
      const context = await pageAll(client, "get_feature_context", { task: "payment processing service", max_tokens: 1500 }, (p) => p.data.packet.files.map((f: { path: string }) => f.path));
      expect(context.pages).toBeGreaterThan(1);
      expect(new Set(context.seen).size).toBe(context.seen.length);
      expect(context.seen.length).toBeGreaterThanOrEqual(20); // every page returned files and the cursor resumed after the last one returned
    } finally {
      await client.close();
    }
  }, 120_000);

  it("the caller's max_tokens bounds the WHOLE response, and a budget too small for any result does not advance the cursor", async () => {
    const ctx = await indexed(manyPayments());
    const client = new McpClient(ctx.repo, ctx.home);
    try {
      await client.initialize();
      for (const max of [1000, 1500, 3000, 8000]) {
        const r = await client.tool("get_feature_context", { task: "payment processing service", max_tokens: max });
        expect(r.payload.estimatedTokens, `max_tokens ${max}`).toBeLessThanOrEqual(max);
        expect(r.raw.length / 3).toBeLessThanOrEqual(max * 1.05);
      }
      expect((await client.request("tools/call", { name: "get_feature_context", arguments: { task: "payment", max_tokens: 500 } })).error?.code).toBe(-32602);
    } finally {
      await client.close();
    }
  });

  it("error responses obey the size cap (a file with thousands of same-name declarations)", async () => {
    const overloads = Array.from({ length: 3000 }, (_, i) => `export function dup(a${i}: number): void;`).join("\n");
    const ctx = await indexed({ "src/dup.ts": `${overloads}\nexport function dup(a: number) {}\n` });
    const client = new McpClient(ctx.repo, ctx.home);
    try {
      await client.initialize();
      const r = await client.tool("get_symbol_references", { symbol: "src/dup.ts#dup" });
      expect(r.isError).toBe(true);
      expect(r.raw.length).toBeLessThan(1000);
    } finally {
      await client.close();
    }
  });

  it("the header and the data always describe ONE generation, even if an indexer publishes during the call", async () => {
    const ctx = await indexed({ "src/a.ts": "export function original() {}\n" });
    const hardened = new HardenedGit();
    const home = { ...process.env, ENGBRAIN_HOME: ctx.home };
    const info = await readGitInfo(ctx.repo, hardened, process.env["HOME"]);
    const store = await Store.openReadOnly({ root: ctx.repo, git: info, hardenedGit: hardened, installId: getInstallId(home) });
    try {
      let published = false;
      const lines: string[] = [];
      const server = new McpServer({
        db: store.db, root: ctx.repo, storeDir: store.dir, version: "t", write: (t) => void lines.push(t),
        freshness: async () => {
          const report = await checkFreshness(store, info, hardened, { verify: false });
          if (!published) {
            published = true;
            writeFileSync(join(ctx.repo, "src/b.ts"), "export function addedLater() {}\n");
            await reindex(ctx); // a new generation is published AFTER freshness was computed for the old one
          }
          return report;
        }
      });
      await server.handle({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18" } });
      const out = await server.handle({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "find_symbol", arguments: { name: "addedLater" } } });
      const payload = JSON.parse(JSON.parse(out!).result.content[0].text);
      const sawNew = payload.data.symbols.length === 1;
      expect(payload.generationId).toBe(sawNew ? 2 : 1); // header generation matches what the data was read from
      expect(payload.uncertainty.join(" ")).toMatch(/updated while this call ran/);
    } finally {
      store.close();
      hardened.dispose();
    }
  });

  it("does not read through a symlinked PARENT directory", async () => {
    const outside = tempDir("engbrain-outdir-");
    writeFileSync(join(outside, "passwd"), "outside content\n");
    const ctx = await indexed({ ...FIVE_MODULES, "a/passwd": "inside content\n" });
    renameSync(join(ctx.repo, "a"), join(ctx.repo, "a-moved"));
    symlinkSync(outside, join(ctx.repo, "a"));
    const client = new McpClient(ctx.repo, ctx.home);
    try {
      await client.initialize();
      const r = await client.tool("check_freshness", { paths: ["a/passwd"] });
      expect(r.payload.data.files[0]).toMatchObject({ state: "outside_root", currentHash: null });
      expect(r.raw).not.toContain(createHash("sha256").update("outside content\n").digest("hex"));
    } finally {
      await client.close();
    }
  });

  it("--fail-on-stale and check_freshness are never answered from the 5 s freshness cache", async () => {
    const ctx = await indexed(FIVE_MODULES);
    const strict = new McpClient(ctx.repo, ctx.home, ["--fail-on-stale"]);
    const plain = new McpClient(ctx.repo, ctx.home);
    try {
      await strict.initialize();
      await plain.initialize();
      expect((await strict.tool("search_code", { query: "login" })).isError).toBe(false); // primes any cache
      expect((await plain.tool("search_code", { query: "login" })).payload.freshness.level).toBe("heuristic");
      writeFileSync(join(ctx.repo, "src/auth/login.ts"), `${FIVE_MODULES["src/auth/login.ts"]}// edited just now\n`);
      const s = await strict.tool("search_code", { query: "login" });
      expect(s.payload.error?.code).toBe("stale_index");
      const f = await plain.tool("check_freshness", { paths: ["src/auth/login.ts"] });
      expect(f.payload.data.files[0].state).toBe("changed");
      expect(f.payload.data.repository.level).toBe("stale"); // consistent with its own per-file answer
    } finally {
      await strict.close();
      await plain.close();
    }
  });

  it("protocol edge cases: invalid ids are not echoed, null ids are rejected, a null-JSON cursor is an argument error", async () => {
    const ctx = await indexed(FIVE_MODULES);
    const client = new McpClient(ctx.repo, ctx.home);
    try {
      await client.initialize();
      client.sendRaw(`${JSON.stringify({ jsonrpc: "2.0", id: { a: 1 }, method: "ping" })}\n`);
      client.sendRaw(`${JSON.stringify({ jsonrpc: "2.0", id: null, method: "ping" })}\n`);
      expect((await client.request("ping")).result).toEqual({});
      const invalid = client.stdoutLines.filter((l) => l.includes("invalid request"));
      expect(invalid).toHaveLength(2);
      expect(invalid.every((l) => JSON.parse(l).id === null)).toBe(true);
      const nullCursor = await client.tool("search_code", { query: "login", cursor: "bnVsbA" });
      expect(nullCursor.isError).toBe(true);
      expect(nullCursor.payload.error.code).toBe("invalid_argument");
    } finally {
      await client.close();
    }
  });

  it("search hits and symbols carry the extractor id AND version in their provenance", async () => {
    const ctx = await indexed(FIVE_MODULES);
    const client = new McpClient(ctx.repo, ctx.home);
    try {
      await client.initialize();
      const r = await client.tool("search_code", { query: "login", kinds: ["function"] });
      expect(r.payload.data.hits[0].provenance.extractorVersion).toEqual(expect.any(String));
    } finally {
      await client.close();
    }
  });

  it("agents never corrupts user config: symlinked dotfile, TOML spellings, non-object JSON", async () => {
    const ctx = await indexed(FIVE_MODULES);
    const fakeHome = tempDir("engbrain-agenthome2-");
    const env = { HOME: fakeHome };
    const dots = tempDir("engbrain-dots-");
    mkdirSync(join(fakeHome, ".codex"));
    writeFileSync(join(dots, "config.toml"), "model = \"x\"\n", { mode: 0o644 });
    symlinkSync(join(dots, "config.toml"), join(fakeHome, ".codex", "config.toml"));
    expect((await runCli(ctx.repo, ["agents", "--apply", "codex"], ctx.home, env)).code).toBe(0);
    expect(statSync(join(fakeHome, ".codex")).isDirectory()).toBe(true);
    expect(readFileSync(join(dots, "config.toml"), "utf8")).toContain("[mcp_servers.engbrain]"); // written THROUGH the link
    expect(existsSync(join(fakeHome, ".codex", "config.toml")) && statSync(join(dots, "config.toml")).mode & 0o777).toBe(0o644);

    for (const variant of ["[mcp_servers.\"engbrain\"]\ncommand = \"x\"\n", "mcp_servers.engbrain.command = \"x\"\n", "[mcp_servers]\nengbrain = { command = \"x\" }\n"]) {
      writeFileSync(join(dots, "config.toml"), variant);
      expect((await runCli(ctx.repo, ["agents", "--apply", "codex"], ctx.home, env)).code, variant).toBe(3);
      expect(readFileSync(join(dots, "config.toml"), "utf8")).toBe(variant);
    }
    for (const bad of ["[1,2]", "null", "{\"mcpServers\":\"oops\"}"]) {
      writeFileSync(join(ctx.repo, ".mcp.json"), bad);
      expect((await runCli(ctx.repo, ["agents", "--apply", "claude"], ctx.home, env)).code, bad).toBe(3);
      expect(readFileSync(join(ctx.repo, ".mcp.json"), "utf8")).toBe(bad);
    }
  });
});
