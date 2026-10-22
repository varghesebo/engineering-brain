import { isAbsolute, relative, resolve } from "node:path";
import { EngbrainError, toStorePath } from "@engbrain/core";

/** Turns a user-supplied path (relative to the current directory, or absolute) into a repo-relative store path. */
export function toRepoPath(root: string, cwd: string, input: string): string {
  const relativePath = relative(root, resolve(cwd, input));
  if (relativePath === "" || relativePath.startsWith("..") || isAbsolute(relativePath)) {
    throw new EngbrainError("INVALID_ROOT", "that path is outside the repository");
  }
  const stored = toStorePath(relativePath);
  if (!stored.ok) {
    throw new EngbrainError("INVALID_ROOT", `that path is not a valid repository path (${stored.reason})`);
  }
  return stored.path;
}
