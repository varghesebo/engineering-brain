/**
 * Default-offline policy. Three guarantees stay separate (see docs/security.md):
 *  1. our own code makes no network calls            (design + tests)
 *  2. third-party code / child processes cannot      (needs verified OS isolation)
 *  3. cloud agents do not transmit code              (outside our control, never claimed)
 *
 * Foundation implements no OS sandbox. A spike observed macOS `sandbox-exec` blocking network for
 * a process and its children, but it is deprecated, not integrated here, and Linux/Windows are untested.
 * Therefore classes C and D are refused: strict mode never silently falls back to unrestricted execution.
 */
export type OperationClass =
  | "in-process" // class A: parsing, SQLite, retrieval
  | "hardened-git" // class B: allowlisted read-only git
  | "repo-influenced-child" // class C: optional indexers reading repo build config
  | "repo-test-execution"; // class D: running repository tests

export interface IsolationStatus {
  available: boolean;
  /** true only when a startup self-test proved isolation in this run. */
  verified: boolean;
  mechanism: string | null;
  reason: string;
}

export type Authorization =
  | { allowed: true }
  | { allowed: false; code: "ISOLATION_UNAVAILABLE"; reason: string };

export function checkIsolation(): IsolationStatus {
  return {
    available: false,
    verified: false,
    mechanism: null,
    reason:
      "No verified OS isolation mechanism is implemented in v0.1 Foundation. " +
      "Operations that run repository-influenced code are refused in strict offline mode."
  };
}

export function authorizeOperation(
  operation: OperationClass,
  isolation: () => IsolationStatus = checkIsolation
): Authorization {
  if (operation === "in-process" || operation === "hardened-git") {
    return { allowed: true };
  }
  const status = isolation();
  if (status.available && status.verified) {
    return { allowed: true };
  }
  return { allowed: false, code: "ISOLATION_UNAVAILABLE", reason: status.reason };
}
