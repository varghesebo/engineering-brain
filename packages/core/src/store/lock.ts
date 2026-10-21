import { randomUUID } from "node:crypto";
import { closeSync, linkSync, openSync, readFileSync, renameSync, rmSync, statSync, writeSync } from "node:fs";
import { hostname } from "node:os";
import { join } from "node:path";
import { EngbrainError } from "../errors.js";

interface LockInfo {
  pid: number;
  host: string;
  token: string;
  startedAtMs: number;
}

export interface WriterLock {
  release(): void;
}

export interface LockOptions {
  timeoutMs?: number;
  pollMs?: number;
  /** Cross-host locks cannot be probed for liveness, so they only expire by age (shared FS is unsupported anyway). */
  foreignHostStaleAfterMs?: number;
  pid?: number;
  host?: string;
  isProcessAlive?: (pid: number) => boolean;
  /** Test hook: runs while this contender holds the takeover lock, after it judged the lock stale. */
  onStaleJudged?: () => void | Promise<void>;
}

function defaultIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    // EPERM = exists but not ours; ESRCH = gone
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

function readLock(path: string): LockInfo | "unreadable" {
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as Partial<LockInfo>;
    if (typeof parsed.pid === "number" && typeof parsed.host === "string" && typeof parsed.token === "string") {
      return { pid: parsed.pid, host: parsed.host, token: parsed.token, startedAtMs: parsed.startedAtMs ?? 0 };
    }
  } catch {
    // empty/partial file: its creator may still be writing
  }
  return "unreadable";
}

function tryCreate(path: string, info: LockInfo): boolean {
  let fd: number;
  try {
    fd = openSync(path, "wx", 0o600);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      return false;
    }
    throw error;
  }
  try {
    writeSync(fd, JSON.stringify(info));
  } finally {
    closeSync(fd);
  }
  return true;
}

type Resolved = Required<Omit<LockOptions, "timeoutMs" | "pollMs" | "onStaleJudged">>;

function isStale(path: string, options: Resolved): LockInfo | null {
  const info = readLock(path);
  if (info === "unreadable") {
    // creator may be mid-write; only treat as stale if it has sat empty for a while
    try {
      return Date.now() - statSync(path).mtimeMs > 10_000 ? { pid: -1, host: "", token: "", startedAtMs: 0 } : null;
    } catch {
      return null;
    }
  }
  if (info.host === options.host) {
    return options.isProcessAlive(info.pid) ? null : info;
  }
  return Date.now() - info.startedAtMs > options.foreignHostStaleAfterMs ? info : null;
}

/**
 * Removes a lock judged stale, serialised through a short-lived takeover lock so two contenders cannot both
 * replace the file and then each believe they own the fresh one. Under the takeover lock the staleness verdict
 * is re-checked against the SAME token. If the file moved aside turns out not to be the one judged stale (an owner
 * changed it), it is put back without overwriting anything.
 */
async function tryTakeOver(path: string, options: Resolved, onStaleJudged: LockOptions["onStaleJudged"]): Promise<boolean> {
  const takeoverPath = `${path}.takeover`;
  const marker: LockInfo = { pid: options.pid, host: options.host, token: randomUUID(), startedAtMs: Date.now() };
  if (!tryCreate(takeoverPath, marker)) {
    // a crashed contender can leave the takeover lock behind; it only ever lives for microseconds
    try {
      if (Date.now() - statSync(takeoverPath).mtimeMs > 5_000) {
        rmSync(takeoverPath, { force: true });
      }
    } catch {
      // vanished
    }
    return false;
  }
  try {
    const judged = isStale(path, options);
    if (judged === null) {
      return false;
    }
    await onStaleJudged?.();
    const aside = `${path}.stale-${randomUUID()}`;
    try {
      renameSync(path, aside);
    } catch {
      return true; // already gone: the slot is free to try
    }
    const moved = readLock(aside);
    const movedToken = moved === "unreadable" ? "" : moved.token;
    if (movedToken !== judged.token) {
      try {
        linkSync(aside, path); // restore the live lock we displaced; fails (harmlessly) if someone re-created it
      } catch {
        // cannot restore; the displaced owner will see a token mismatch on release and not delete the new lock
      }
    }
    rmSync(aside, { force: true });
    return movedToken === judged.token;
  } finally {
    rmSync(takeoverPath, { force: true });
  }
}

/**
 * Single-writer lock using exclusive file creation (works on Windows; no flock assumptions).
 * Stale takeover is serialised (see tryTakeOver).
 * Limitation: pid reuse can make a dead owner look alive; the lock then waits until timeout (fail-safe).
 */
export async function acquireWriterLock(storeDir: string, options: LockOptions = {}): Promise<WriterLock> {
  const path = join(storeDir, "index.lock");
  const resolved: Resolved = {
    pid: options.pid ?? process.pid,
    host: options.host ?? hostname(),
    isProcessAlive: options.isProcessAlive ?? defaultIsAlive,
    foreignHostStaleAfterMs: options.foreignHostStaleAfterMs ?? 6 * 3_600_000
  };
  const timeoutMs = options.timeoutMs ?? 10_000;
  const pollMs = options.pollMs ?? 100;
  const info: LockInfo = { pid: resolved.pid, host: resolved.host, token: randomUUID(), startedAtMs: Date.now() };
  const deadline = Date.now() + timeoutMs;

  for (;;) {
    if (tryCreate(path, info)) {
      return {
        release(): void {
          const current = readLock(path);
          if (current !== "unreadable" && current.token === info.token) {
            rmSync(path, { force: true });
          }
        }
      };
    }
    if (isStale(path, resolved) !== null && (await tryTakeOver(path, resolved, options.onStaleJudged))) {
      continue; // the stale lock is gone; try to create ours immediately
    }
    if (Date.now() >= deadline) {
      throw new EngbrainError("LOCK_TIMEOUT", "another engbrain process is writing to this store; try again shortly");
    }
    await new Promise((resolve) => setTimeout(resolve, pollMs));
  }
}
