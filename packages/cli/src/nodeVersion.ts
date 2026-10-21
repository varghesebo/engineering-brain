/** Minimum runtime: better-sqlite3 13 requires Node >= 22 (spike S1/S2); we require 22.13+ like the other dependencies. */
export const MINIMUM_NODE = "22.13.0";

export function nodeVersionProblem(version: string = process.versions.node): string | null {
  const [major = 0, minor = 0] = version.split(".").map(Number);
  if (major > 22 || (major === 22 && minor >= 13)) {
    return null;
  }
  return `engbrain requires Node.js ${MINIMUM_NODE} or newer (found ${version}).`;
}
