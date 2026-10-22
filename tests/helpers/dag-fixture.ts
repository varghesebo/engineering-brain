import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { git, makeGitRepo, writeFiles } from "./env.js";

export interface Dag {
  repo: string;
  /** commit ids by label */
  c: Record<string, string>;
}

export const sh = (repo: string, args: string[]): string => git(repo, args).trim();

/** Commits whatever is in the working tree (synthetic fixture repos only). */
export function commitAll(repo: string, message: string): string {
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "--allow-empty", "-m", message]);
  return sh(repo, ["rev-parse", "HEAD"]);
}

export const API_V1 = "export function getUser(id: string) {\n  return { id };\n}\nexport function helper() {\n  return 1;\n}\n";

/**
 * A: root. B: modifies the shared API. C: fixes the test. D: renames a function and a file.
 * E: a branch from B, merged into main through a two-parent merge M.
 */
export function buildDag(): Dag {
  const repo = makeGitRepo({}, false);
  const c: Record<string, string> = {};
  writeFiles(repo, { "src/api.ts": API_V1, "src/api.test.ts": "import { getUser } from \"./api\";\nexport const t = getUser(\"a\");\n", "src/util.ts": "export const util = 1;\n" });
  c["A"] = commitAll(repo, "A root");
  writeFiles(repo, { "src/api.ts": API_V1.replace("getUser(id: string)", "getUser(id: string, verbose?: boolean)") });
  c["B"] = commitAll(repo, "B modifies shared API");
  git(repo, ["checkout", "-q", "-b", "feature-e"]);
  writeFiles(repo, { "src/extra.ts": "export const extra = 2;\n" });
  c["E"] = commitAll(repo, "E feature branch");
  git(repo, ["checkout", "-q", "main"]);
  writeFiles(repo, { "src/api.test.ts": "import { getUser } from \"./api\";\nexport const t = getUser(\"a\", true);\n" });
  c["C"] = commitAll(repo, "C fixes test");
  git(repo, ["mv", "src/util.ts", "src/helpers.ts"]);
  writeFiles(repo, { "src/api.ts": readApi(repo).replace("function getUser", "function fetchUser") });
  c["D"] = commitAll(repo, "D renames function and file");
  git(repo, ["merge", "-q", "--no-ff", "-m", "M merge feature-e", "feature-e"]);
  c["M"] = sh(repo, ["rev-parse", "HEAD"]);
  return { repo, c };
}

function readApi(repo: string): string {
  return execFileSync("cat", [join(repo, "src/api.ts")], { encoding: "utf8" });
}
