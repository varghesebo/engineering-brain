import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync, readdirSync, readSync, writeSync } from "node:fs";
import { join } from "node:path";
import { EngbrainError } from "./errors.js";

export interface FileSnapshot {
  data: Buffer;
  size: number;
  mtimeNs: string;
  ctimeNs: string;
  inode: string;
}

export type SafeReadResult =
  | { kind: "ok"; file: FileSnapshot }
  | { kind: "excluded"; reason: "symlink" | "not_regular" | "too_large" }
  | { kind: "missing" };

/**
 * Reads a regular file without following a final symlink (O_NOFOLLOW where the OS has it; on Windows the
 * caller has already lstat-checked and the post-open fstat still requires a regular file). Bounded by `maxBytes`.
 */
export function readRegularFileBounded(absolutePath: string, maxBytes: number): SafeReadResult {
  const noFollow = constants.O_NOFOLLOW ?? 0;
  const nonBlock = constants.O_NONBLOCK ?? 0; // never block on a FIFO/device that replaced the file after lstat
  let fd: number;
  try {
    fd = openSync(absolutePath, constants.O_RDONLY | noFollow | nonBlock);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "ENOTDIR") {
      return { kind: "missing" };
    }
    if (code === "ELOOP" || code === "EMLINK") {
      return { kind: "excluded", reason: "symlink" };
    }
    throw error;
  }
  try {
    const stat = fstatSync(fd, { bigint: true });
    if (!stat.isFile()) {
      return { kind: "excluded", reason: "not_regular" };
    }
    if (stat.size > BigInt(maxBytes)) {
      return { kind: "excluded", reason: "too_large" };
    }
    const size = Number(stat.size);
    const data = Buffer.allocUnsafe(size);
    let offset = 0;
    while (offset < size) {
      const read = readSync(fd, data, offset, size - offset, offset);
      if (read === 0) {
        break;
      }
      offset += read;
    }
    return {
      kind: "ok",
      file: {
        data: offset === size ? data : data.subarray(0, offset),
        size: offset,
        mtimeNs: stat.mtimeNs.toString(),
        ctimeNs: stat.ctimeNs.toString(),
        inode: stat.ino.toString()
      }
    };
  } finally {
    closeSync(fd);
  }
}

export function readTextFileBounded(path: string, maxBytes: number): string | null {
  const result = readRegularFileBounded(path, maxBytes);
  return result.kind === "ok" ? result.file.data.toString("utf8") : null;
}

export type FilesystemKind = "local" | "network" | "unknown";

const NETWORK_FS_TYPES = new Set(["nfs", "nfs4", "cifs", "smb3", "smbfs", "9p", "afs", "ceph", "glusterfs", "fuse.sshfs"]);

/** Pure parser for Linux /proc/self/mountinfo: picks the longest mount point containing the path. */
export function classifyMountInfo(mountInfo: string, absolutePath: string): FilesystemKind {
  let bestLength = -1;
  let best: FilesystemKind = "unknown";
  for (const line of mountInfo.split("\n")) {
    const separator = line.indexOf(" - ");
    if (separator === -1) {
      continue;
    }
    const mountPoint = line.slice(0, separator).split(" ")[4]?.replace(/\\040/g, " ");
    const fsType = line.slice(separator + 3).split(" ")[0];
    if (mountPoint === undefined || fsType === undefined) {
      continue;
    }
    const matches = absolutePath === mountPoint || absolutePath.startsWith(mountPoint.endsWith("/") ? mountPoint : `${mountPoint}/`);
    if (matches && mountPoint.length > bestLength) {
      bestLength = mountPoint.length;
      best = NETWORK_FS_TYPES.has(fsType) ? "network" : "local";
    }
  }
  return best;
}

/**
 * Best-effort only (SQLite WAL needs shared memory and is unsafe on network filesystems).
 * Linux: mountinfo. Windows: UNC paths. macOS and anything else: "unknown" (not checked).
 */
export function detectFilesystemKind(absolutePath: string, platform: NodeJS.Platform = process.platform): FilesystemKind {
  if (platform === "win32") {
    return absolutePath.startsWith("\\\\") && !absolutePath.startsWith("\\\\?\\") ? "network" : "unknown";
  }
  if (platform === "linux") {
    try {
      return classifyMountInfo(readFileSync("/proc/self/mountinfo", "utf8"), absolutePath);
    } catch {
      return "unknown";
    }
  }
  return "unknown";
}

/** Appends without following a final symlink (a hostile repo could plant a link where a log or ignore file goes). */
export function appendFileNoFollow(path: string, text: string): void {
  const fd = openSync(path, constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | (constants.O_NOFOLLOW ?? 0), 0o600);
  try {
    writeSync(fd, text);
  } finally {
    closeSync(fd);
  }
}

/** Creates a file only if absent, never through a symlink. Returns false when something already exists there. */
export function createFileExclusiveNoFollow(path: string, text: string): boolean {
  let fd: number;
  try {
    fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      return false;
    }
    throw error;
  }
  try {
    writeSync(fd, text);
  } finally {
    closeSync(fd);
  }
  return true;
}

/** A store directory may hold only regular files and (one level of) real directories; any symlink is refused. */
export function assertNoSymlinksIn(directory: string, what: string): void {
  for (const name of readdirSync(directory)) {
    const stat = lstatSync(join(directory, name));
    if (stat.isSymbolicLink()) {
      throw new EngbrainError("STORE_UNSAFE_PATH", `${what} contains a symlink (${name.slice(0, 60)}); refusing to use it`);
    }
  }
}
