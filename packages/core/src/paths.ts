import { isAbsolute, relative, resolve, sep } from "node:path";

const WINDOWS_RESERVED = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/i;

/** True when `candidate` is `root` or inside it (lexical check on already-resolved absolute paths). */
export function isInside(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

export type StorePathResult = { ok: true; path: string } | { ok: false; reason: string };

/**
 * Normalises a repository-relative path to the stored form: forward slashes, NFC, case preserved.
 * Rejects anything that could escape the root or is not a well-formed name.
 */
export function toStorePath(platformRelativePath: string): StorePathResult {
  if (platformRelativePath === "" || platformRelativePath.includes("\0")) {
    return { ok: false, reason: "invalid_path" };
  }
  const slashed = sep === "\\" ? platformRelativePath.split("\\").join("/") : platformRelativePath;
  const normalized = slashed.normalize("NFC");
  if (normalized.startsWith("/") || /^[A-Za-z]:/.test(normalized)) {
    return { ok: false, reason: "invalid_path" };
  }
  for (const component of normalized.split("/")) {
    if (component === "" || component === "." || component === "..") {
      return { ok: false, reason: "invalid_path" };
    }
    // ':' enables drive-relative paths and alternate data streams on Windows; trailing dot/space is not a real name there.
    if (component.includes(":") || /[. ]$/.test(component)) {
      return { ok: false, reason: "invalid_path" };
    }
    if (WINDOWS_RESERVED.test(component.split(".")[0] ?? "")) {
      return { ok: false, reason: "reserved_name" };
    }
  }
  return { ok: true, path: normalized };
}

/** Key under which two paths collide on case-insensitive or normalising filesystems. */
export function collisionKey(storePath: string): string {
  return storePath.normalize("NFC").toLowerCase();
}

export function absoluteFromStorePath(root: string, storePath: string): string {
  return resolve(root, ...storePath.split("/"));
}

/** Repo-relative path as listed on disk (any normalisation) -> absolute path, or null if it would leave the root. */
export function resolveUnderRoot(root: string, rawPath: string): string | null {
  const absolute = resolve(root, ...rawPath.split("/"));
  return isInside(root, absolute) && absolute !== root ? absolute : null;
}
