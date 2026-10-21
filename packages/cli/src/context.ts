import { homedir } from "node:os";
import { EngbrainError, getInstallId, nonGitInfo, readGitInfo, type GitInfo } from "@engbrain/core";
import { GitError, HardenedGit } from "@engbrain/security";

export interface CliContext {
  root: string;
  git: GitInfo;
  hardenedGit: HardenedGit | null;
  installId: string;
  /** Releases the git scratch directory. */
  dispose(): void;
}

/** The home directory as seen through the supplied environment (falls back to the OS value). */
function homeFrom(env: NodeJS.ProcessEnv): string {
  return env["HOME"] ?? env["USERPROFILE"] ?? homedir();
}

/** Resolves the repository root and git facts (hardened git only) for the directory the user pointed at. */
export async function resolveContext(startDir: string, env: NodeJS.ProcessEnv): Promise<CliContext> {
  let hardenedGit: HardenedGit | null = null;
  try {
    hardenedGit = new HardenedGit();
  } catch (error) {
    if (!(error instanceof GitError) || error.code !== "GIT_NOT_FOUND") {
      throw error;
    }
  }
  try {
    const git = hardenedGit === null ? nonGitInfo(startDir, homeFrom(env)) : await readGitInfo(startDir, hardenedGit, homeFrom(env));
    return { root: git.root, git, hardenedGit, installId: getInstallId(env), dispose: () => hardenedGit?.dispose() };
  } catch (error) {
    hardenedGit?.dispose();
    if (error instanceof EngbrainError || error instanceof GitError) {
      throw error;
    }
    throw new EngbrainError("INTERNAL", error instanceof Error ? error.message : "unexpected error");
  }
}
