import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { installNetworkGuard } from "@engbrain/security";
import { afterAll, describe, expect, it } from "vitest";
import { cleanupTempDirs, engbrainHome, makeGitRepo, runCli } from "../helpers/env.js";
import { generateRepoFiles } from "../helpers/fixtures.js";

afterAll(cleanupTempDirs);

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const NETWORK_MODULES = ["net", "http", "https", "http2", "dns", "dns/promises", "tls", "dgram", "inspector", "cluster", "worker_threads"];

function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== "node_modules" && entry.name !== "dist" && entry.name !== "test") {
        sourceFiles(full, out);
      }
    } else if (entry.name.endsWith(".ts")) {
      out.push(full);
    }
  }
  return out;
}

const files = readdirSync(join(ROOT, "packages")).flatMap((pkg) => sourceFiles(join(ROOT, "packages", pkg, "src")));
const rel = (f: string): string => relative(ROOT, f).split("\\").join("/");
// The network guard is the test instrument: it must import network modules in order to patch them.
const GUARD = "packages/security/src/networkGuard.ts";
const SPAWNER = "packages/security/src/git.ts";

describe("T7 our own code makes no network calls (guarantee 1: static + runtime)", () => {
  it("scans the expected source set", () => {
    expect(files.length).toBeGreaterThan(20);
  });

  it("no source file imports a network-capable Node module (except the test guard)", () => {
    const offenders: string[] = [];
    for (const file of files) {
      const text = readFileSync(file, "utf8");
      for (const mod of NETWORK_MODULES) {
        const pattern = new RegExp(`(?:from|import|require)\\s*\\(?\\s*["'](?:node:)?${mod.replace("/", "\\/")}["']`);
        if (pattern.test(text) && rel(file) !== GUARD) {
          offenders.push(`${rel(file)} -> ${mod}`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  it("no ambient network APIs (fetch, XMLHttpRequest, WebSocket, sendBeacon) are referenced", () => {
    const offenders = files
      .filter((f) => rel(f) !== GUARD)
      .filter((f) => /\b(fetch\s*\(|XMLHttpRequest|WebSocket|sendBeacon|EventSource)\b/.test(readFileSync(f, "utf8")))
      .map(rel);
    expect(offenders).toEqual([]);
  });

  it("child_process is used only by the hardened git module", () => {
    const users = files.filter((f) => /["'](?:node:)?child_process["']/.test(readFileSync(f, "utf8"))).map(rel);
    expect(users).toEqual([SPAWNER]);
  });

  it("only vetted runtime dependencies are declared (no HTTP clients, telemetry or cloud SDKs)", () => {
    const allowed = new Set(["better-sqlite3", "picomatch", "@engbrain/core", "@engbrain/security", "@engbrain/cli"]);
    for (const pkg of readdirSync(join(ROOT, "packages"))) {
      const manifest = JSON.parse(readFileSync(join(ROOT, "packages", pkg, "package.json"), "utf8")) as { dependencies?: Record<string, string> };
      for (const dep of Object.keys(manifest.dependencies ?? {})) {
        expect(allowed.has(dep), `${pkg} depends on ${dep}`).toBe(true);
      }
    }
  });

  it("pins runtime dependency versions exactly", () => {
    for (const pkg of readdirSync(join(ROOT, "packages"))) {
      const manifest = JSON.parse(readFileSync(join(ROOT, "packages", pkg, "package.json"), "utf8")) as { dependencies?: Record<string, string> };
      for (const [name, version] of Object.entries(manifest.dependencies ?? {})) {
        expect(version, `${pkg}:${name}`).toMatch(/^\d+\.\d+\.\d+$/);
      }
    }
  });

  it("every CLI command completes with the in-process network guard installed and zero attempts", async () => {
    const guard = installNetworkGuard();
    try {
      const home = engbrainHome();
      const repo = makeGitRepo(generateRepoFiles(8, 21));
      const runs = [
        ["init"], ["index"], ["index"], ["status", "--check"], ["status", "--json"], ["gc"], ["uninstall"], ["uninstall", "--purge", "--yes"]
      ];
      for (const args of runs) {
        const result = await runCli(repo, args, home);
        expect(result.code, `${args.join(" ")}: ${result.stderr}`).toBe(0);
      }
      expect(guard.attempts).toEqual([]);
    } finally {
      guard.uninstall();
    }
  });

  it("negative control: the guard really would catch a network attempt", () => {
    const guard = installNetworkGuard();
    try {
      expect(() => globalThis.fetch("http://127.0.0.1:9/")).toThrow(/blocked/);
      expect(guard.attempts.map((a) => a.api)).toContain("fetch");
    } finally {
      guard.uninstall();
    }
  });
});

describe("T8 strict offline fails closed (no execution of repository-influenced code exists)", () => {
  it("verify, mcp, context and agents are refused as unavailable", async () => {
    const home = engbrainHome();
    const repo = makeGitRepo({ "a.ts": "export const a = 1;\n" });
    for (const command of ["verify", "mcp", "context", "agents"]) {
      const result = await runCli(repo, [command, "--run"], home);
      expect(result.code).toBe(2);
      expect(result.stderr).toContain("not available");
    }
  });

  it("status reports OS isolation honestly as unavailable", async () => {
    const home = engbrainHome();
    const repo = makeGitRepo({ "a.ts": "export const a = 1;\n" });
    await runCli(repo, ["init"], home);
    const status = await runCli(repo, ["status", "--json"], home);
    const parsed = JSON.parse(status.stdout) as { offline: { applicationNetworkCalls: string; osIsolation: string } };
    expect(parsed.offline).toMatchObject({ applicationNetworkCalls: "none", osIsolation: "unavailable" });
    expect(status.stdout).not.toMatch(/sandbox(ed)? (enabled|active)|isolated: true/i);
  });
});
