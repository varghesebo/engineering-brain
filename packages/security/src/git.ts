import { execFile } from "node:child_process";
import { accessSync, constants, mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, isAbsolute, join } from "node:path";

/**
 * Hardened git execution. Repository content and `.git/config` are untrusted: a plain
 * `git status` was observed to execute a repo-defined `core.fsmonitor` command, so every call
 * goes through this module. Only a small read-only subcommand allowlist is permitted, and none of
 * the allowed subcommands refresh the index or run attribute filters.
 */
export const ALLOWED_GIT_SUBCOMMANDS = ["rev-parse", "ls-files", "rev-list", "symbolic-ref", "diff-tree", "cat-file", "merge-base", "ls-tree"] as const;
export type GitSubcommand = (typeof ALLOWED_GIT_SUBCOMMANDS)[number];

/**
 * Arguments that could run a program, read a path chosen by the caller, write a file or change which repository is read.
 * `--output` writes a file; `--filters`/`--textconv`/`--ext-diff` run configured programs; `-O` reads an order file; `--open-files-in-pager` starts a pager;
 * `-c` is also diff-tree's combined-merge flag (never wanted here); `log` is not allowlisted at all (signature display can run gpg).
 */
const FORBIDDEN_ARG = /^(-c|--config|--exec-path|--upload-pack|--receive-pack|--ext-diff|--textconv|--filters|--output|--open-files-in-pager|-O|--git-dir|--work-tree|--no-index)/;
const WINDOWS_ENV_PASSTHROUGH = ["SystemRoot", "SYSTEMROOT", "TEMP", "TMP", "ComSpec"];

export class GitError extends Error {
  constructor(
    message: string,
    readonly code: "GIT_NOT_FOUND" | "GIT_DISALLOWED" | "GIT_FAILED" | "GIT_TIMEOUT" | "GIT_OUTPUT_TOO_LARGE",
    readonly exitCode: number | null = null
  ) {
    super(message);
    this.name = "GitError";
  }
}

export interface HardenedGitOptions {
  /** Absolute path to the git binary. When omitted it is resolved from PATH, ignoring relative entries. */
  gitBinary?: string;
  timeoutMs?: number;
  maxBufferBytes?: number;
}

/** Finds git on PATH without ever considering the working directory (a repo could plant git.exe). */
export function resolveGitBinary(env: NodeJS.ProcessEnv = process.env, platform: NodeJS.Platform = process.platform): string | null {
  const names = platform === "win32" ? ["git.exe"] : ["git"];
  const pathValue = env["PATH"] ?? env["Path"] ?? "";
  for (const entry of pathValue.split(delimiter)) {
    if (entry === "" || !isAbsolute(entry)) {
      continue;
    }
    for (const name of names) {
      const candidate = join(entry, name);
      try {
        if (statSync(candidate).isFile()) {
          accessSync(candidate, constants.X_OK);
          return candidate;
        }
      } catch {
        // not here
      }
    }
  }
  return null;
}

export class HardenedGit {
  private readonly gitBinary: string;
  private readonly timeoutMs: number;
  private readonly maxBufferBytes: number;
  private scratch: string | null = null;

  constructor(options: HardenedGitOptions = {}) {
    const binary = options.gitBinary ?? resolveGitBinary();
    if (binary === null) {
      throw new GitError("git executable not found on PATH", "GIT_NOT_FOUND");
    }
    this.gitBinary = binary;
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.maxBufferBytes = options.maxBufferBytes ?? 256 * 1024 * 1024;
  }

  /** Random private scratch dir holding an empty hooks dir and empty config files (platform-safe, no /dev/null). */
  private scratchDir(): string {
    if (this.scratch === null) {
      this.scratch = mkdtempSync(join(tmpdir(), "engbrain-git-"));
      mkdirSync(join(this.scratch, "hooks"));
      writeFileSync(join(this.scratch, "empty.gitconfig"), "");
    }
    return this.scratch;
  }

  /** Arguments placed before the subcommand; command-line `-c` outranks every config file, including the repo's. */
  buildGlobalArgs(): string[] {
    const scratch = this.scratchDir();
    return [
      "--no-pager",
      "--no-optional-locks",
      "--no-replace-objects",
      "-c", "core.fsmonitor=false",
      "-c", `core.hooksPath=${join(scratch, "hooks")}`,
      "-c", "core.untrackedCache=false",
      "-c", "core.sshCommand=",
      "-c", "protocol.allow=never",
      "-c", "core.commitGraph=false", // a hostile commit-graph file could misreport reachability
      "-c", "gc.auto=0",
      "-c", "diff.renameLimit=1000" // bounds rename-detection CPU whatever the repository configures
    ];
  }

  /** Minimal allowlisted environment; nothing inherited from the caller except PATH and Windows system vars. */
  buildEnv(parent: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
    const scratch = this.scratchDir();
    const env: NodeJS.ProcessEnv = {
      PATH: parent["PATH"] ?? parent["Path"] ?? "",
      HOME: scratch,
      USERPROFILE: scratch,
      XDG_CONFIG_HOME: scratch,
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: join(scratch, "empty.gitconfig"),
      GIT_TERMINAL_PROMPT: "0",
      GIT_OPTIONAL_LOCKS: "0",
      GIT_NO_LAZY_FETCH: "1", // a partial clone must never try to fetch missing objects
      GIT_PAGER: "cat",
      LC_ALL: "C"
    };
    for (const key of WINDOWS_ENV_PASSTHROUGH) {
      if (parent[key] !== undefined) {
        env[key] = parent[key];
      }
    }
    return env;
  }

  async run(cwd: string, args: readonly string[]): Promise<string> {
    return (await this.exec(cwd, args, "utf8", {})) as string;
  }

  /** Like `run`, but returns raw bytes and can feed stdin (for `cat-file --batch`). The same allowlist, forbidden arguments and environment apply. */
  async runBuffer(cwd: string, args: readonly string[], options: { input?: string | Buffer; maxBufferBytes?: number } = {}): Promise<Buffer> {
    return (await this.exec(cwd, args, "buffer", options)) as Buffer;
  }

  private exec(cwd: string, args: readonly string[], encoding: "utf8" | "buffer", options: { input?: string | Buffer; maxBufferBytes?: number }): Promise<string | Buffer> {
    const subcommand = args[0];
    if (subcommand === undefined || !(ALLOWED_GIT_SUBCOMMANDS as readonly string[]).includes(subcommand)) {
      throw new GitError(`git subcommand not allowed: ${String(subcommand)}`, "GIT_DISALLOWED");
    }
    const bad = args.find((arg) => FORBIDDEN_ARG.test(arg));
    if (bad !== undefined) {
      throw new GitError(`git argument not allowed: ${bad}`, "GIT_DISALLOWED");
    }
    const fullArgs = [...this.buildGlobalArgs(), ...args];
    return new Promise<string | Buffer>((resolve, reject) => {
      const child = execFile(
        this.gitBinary,
        fullArgs,
        { cwd, env: this.buildEnv(), timeout: this.timeoutMs, maxBuffer: options.maxBufferBytes ?? this.maxBufferBytes, windowsHide: true, encoding, shell: false },
        (error, stdout, stderr) => {
          if (error === null) {
            resolve(stdout);
            return;
          }
          const failure = error as NodeJS.ErrnoException & { killed?: boolean; code?: number | string };
          if (failure.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER") {
            reject(new GitError(`git ${subcommand} output exceeded the size limit`, "GIT_OUTPUT_TOO_LARGE"));
            return;
          }
          if (failure.killed === true) {
            reject(new GitError(`git ${subcommand} timed out`, "GIT_TIMEOUT"));
            return;
          }
          const exitCode = typeof failure.code === "number" ? failure.code : null;
          reject(new GitError(`git ${subcommand} failed: ${stderr.toString().trim().slice(0, 300)}`, "GIT_FAILED", exitCode));
        }
      );
      if (options.input !== undefined) {
        child.stdin?.on("error", () => undefined); // the process may exit before reading all input; its exit status is reported above
        child.stdin?.end(options.input);
      }
    });
  }

  dispose(): void {
    if (this.scratch !== null) {
      rmSync(this.scratch, { recursive: true, force: true });
      this.scratch = null;
    }
  }
}
