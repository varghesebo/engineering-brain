import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { main } from "@engbrain/cli";

const cleanups: string[] = [];

export function tempDir(prefix = "engbrain-test-"): string {
  const dir = realpathSync.native(mkdtempSync(join(tmpdir(), prefix)));
  cleanups.push(dir);
  return dir;
}

export function cleanupTempDirs(): void {
  for (const dir of cleanups.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Plain git for building SYNTHETIC fixture repos only (never used on hostile repos; those use fixed arguments). */
export function git(cwd: string, args: string[], env: NodeJS.ProcessEnv = {}): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    env: {
      PATH: process.env["PATH"] ?? "",
      HOME: tempHome,
      GIT_CONFIG_GLOBAL: join(tempHome, "gitconfig"),
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.invalid",
      GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.invalid",
      ...env
    }
  });
}

const tempHome = tempDir("engbrain-home-");
writeFileSync(join(tempHome, "gitconfig"), "[init]\n\tdefaultBranch = main\n");

export function writeFiles(root: string, files: Map<string, string> | Record<string, string>): void {
  const entries = files instanceof Map ? [...files.entries()] : Object.entries(files);
  for (const [path, content] of entries) {
    const target = join(root, ...path.split("/"));
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, content);
  }
}

export function makeGitRepo(files: Map<string, string> | Record<string, string>, commit = true): string {
  const root = tempDir("engbrain-repo-");
  git(root, ["init", "-q"]);
  writeFiles(root, files);
  if (commit) {
    git(root, ["add", "-A"]);
    git(root, ["commit", "-q", "-m", "initial"]);
  }
  return root;
}

export interface CliRun {
  code: number;
  stdout: string;
  stderr: string;
}

export function engbrainHome(): string {
  return tempDir("engbrain-userhome-");
}

/** Runs the real CLI entry point in-process with an isolated user config dir. */
export async function runCli(cwd: string, args: string[], home: string, extraEnv: NodeJS.ProcessEnv = {}): Promise<CliRun> {
  let stdout = "";
  let stderr = "";
  const code = await main(args, {
    stdout: (text) => void (stdout += text),
    stderr: (text) => void (stderr += text),
    env: { ...process.env, ENGBRAIN_HOME: home, ...extraEnv },
    cwd
  });
  return { code, stdout, stderr };
}

import { Store, getInstallId, readGitInfo, type GitInfo } from "@engbrain/core";
import { HardenedGit } from "@engbrain/security";

export interface Opened {
  store: Store;
  info: GitInfo;
  git: HardenedGit;
  installId: string;
  close(): void;
}

/** Opens (or with `init: true` creates) the store for a directory, the same way the CLI does. */
export async function openFor(dir: string, home: string, init = false): Promise<Opened> {
  const git = new HardenedGit();
  try {
    const info = await readGitInfo(dir, git);
    const installId = getInstallId({ ...process.env, ENGBRAIN_HOME: home });
    const context = { root: info.root, git: info, hardenedGit: git, installId };
    const store = init ? await Store.init(context) : await Store.open(context);
    return { store, info, git, installId, close: () => { store.close(); git.dispose(); } };
  } catch (error) {
    git.dispose();
    throw error;
  }
}

export interface IndexDump {
  fingerprint: string | null;
  manifest: Array<[string, string | null, string | null]>;
  facts: string[];
}

/** Canonical, order-independent view of the current generation for equivalence checks. */
export function dumpCurrent(store: Store): IndexDump {
  const gen = store.db.prepare("SELECT current_generation_id AS id FROM store_meta").get() as { id: number | null };
  if (gen.id === null) {
    return { fingerprint: null, manifest: [], facts: [] };
  }
  const fp = store.db.prepare("SELECT source_fingerprint AS f FROM generations WHERE id = ?").get(gen.id) as { f: string };
  const manifest = store.db
    .prepare("SELECT path, content_hash, excluded_reason FROM generation_files WHERE generation_id = ? ORDER BY path")
    .all(gen.id) as Array<{ path: string; content_hash: string | null; excluded_reason: string | null }>;
  const facts = store.db
    .prepare(
      `SELECT ff.content_hash || '|' || ff.extractor_id || '@' || ff.extractor_version || '|' || IFNULL(ff.language,'') || '|' || ff.parse_status || '|' || IFNULL(ff.attrs_json,'') AS k
       FROM file_facts ff WHERE ff.content_hash IN (SELECT content_hash FROM generation_files WHERE generation_id = ? AND content_hash IS NOT NULL) ORDER BY k`
    )
    .all(gen.id) as Array<{ k: string }>;
  return { fingerprint: fp.f, manifest: manifest.map((m) => [m.path, m.content_hash, m.excluded_reason]), facts: facts.map((f) => f.k) };
}
