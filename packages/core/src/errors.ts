export type ErrorCode =
  | "INVALID_ROOT"
  | "NOT_INITIALIZED"
  | "ALREADY_INITIALIZED"
  | "STORE_TRACKED_BY_GIT"
  | "STORE_UNSAFE_PATH"
  | "STORE_OWNER_MISMATCH"
  | "STORE_ROOT_MISMATCH"
  | "STORE_NEWER_SCHEMA"
  | "STORE_NEEDS_MIGRATION"
  | "NETWORK_FILESYSTEM"
  | "LOCK_TIMEOUT"
  | "INVALID_CONFIG"
  | "INTEGRITY_FAILED"
  | "POLICY_REFUSED"
  | "GIT_UNAVAILABLE"
  | "INTERNAL";

export class EngbrainError extends Error {
  constructor(
    readonly code: ErrorCode,
    message: string
  ) {
    super(message);
    this.name = "EngbrainError";
  }
}
