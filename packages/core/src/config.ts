import { readTextFileBounded } from "./fsSafe.js";
import { EngbrainError } from "./errors.js";

/**
 * Repository-local config is UNTRUSTED (a cloned repo may ship its own `.engineering-brain/config.json`).
 * It can only add exclusions and tune bounded caps. It cannot disable defaults, name commands or paths to
 * run, or relax the offline policy.
 */
export interface EngbrainConfig {
  version: 1;
  /** Extra deny globs (repo-relative, forward slashes), additive to the built-in defaults. */
  exclude: string[];
  maxFileBytes: number;
  generationsToKeep: number;
  auditMaxFileBytes: number;
  auditMaxFiles: number;
  auditRetentionDays: number;
}

export const DEFAULT_CONFIG: EngbrainConfig = {
  version: 1,
  exclude: [],
  maxFileBytes: 1024 * 1024,
  generationsToKeep: 3,
  auditMaxFileBytes: 5 * 1024 * 1024,
  auditMaxFiles: 5,
  auditRetentionDays: 90
};

const CONFIG_FILE_MAX_BYTES = 64 * 1024;
const BOUNDS = {
  maxFileBytes: [1024, 8 * 1024 * 1024],
  generationsToKeep: [1, 20],
  auditMaxFileBytes: [64 * 1024, 64 * 1024 * 1024],
  auditMaxFiles: [1, 20],
  auditRetentionDays: [1, 3650]
} as const;

function fail(message: string): never {
  throw new EngbrainError("INVALID_CONFIG", message);
}

function boundedInt(key: keyof typeof BOUNDS, value: unknown): number {
  const [min, max] = BOUNDS[key];
  if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > max) {
    return fail(`config.${key} must be an integer between ${min} and ${max}`);
  }
  return value;
}

/**
 * Patterns come from an untrusted file and run against every path. picomatch backtracks exponentially on
 * patterns like `*a*a*a*a*a*b`, so only a small, linear-friendly syntax is accepted: literals, `*`, `**`, `?`,
 * and at most two wildcard runs per path segment. No braces, brackets, extglobs or negation.
 */
const SAFE_GLOB = /^[A-Za-z0-9_.@ /*?-]+$/;
const MAX_WILDCARD_RUNS_PER_SEGMENT = 2;

function isSafeGlob(pattern: string): boolean {
  if (!SAFE_GLOB.test(pattern)) {
    return false;
  }
  return pattern.split("/").every((segment) => (segment.match(/[*?]+/g) ?? []).length <= MAX_WILDCARD_RUNS_PER_SEGMENT);
}

function validateExclude(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > 200) {
    return fail("config.exclude must be an array of at most 200 patterns");
  }
  return value.map((entry, index) => {
    if (typeof entry !== "string" || entry.length === 0 || entry.length > 200 || entry.includes("\0")) {
      return fail(`config.exclude[${index}] must be a non-empty string up to 200 characters`);
    }
    if (entry.startsWith("/") || /^[A-Za-z]:/.test(entry) || entry.split(/[\\/]/).includes("..")) {
      return fail(`config.exclude[${index}] must be a repo-relative pattern without '..'`);
    }
    if (!isSafeGlob(entry)) {
      return fail(`config.exclude[${index}] uses unsupported glob syntax (allowed: letters, digits, . _ - @ space / * ? with at most 2 wildcard runs per segment)`);
    }
    return entry;
  });
}

/** Strict validation: unknown keys and out-of-range values are rejected, never silently accepted. */
export function validateConfig(raw: unknown): EngbrainConfig {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return fail("config must be a JSON object");
  }
  const record = raw as Record<string, unknown>;
  const allowed = new Set(Object.keys(DEFAULT_CONFIG));
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) {
      return fail(`unknown config key: ${key.slice(0, 40)}`);
    }
  }
  if (record["version"] !== undefined && record["version"] !== 1) {
    return fail("unsupported config version");
  }
  const merged = { ...DEFAULT_CONFIG, ...record };
  return {
    version: 1,
    exclude: validateExclude(merged.exclude),
    maxFileBytes: boundedInt("maxFileBytes", merged.maxFileBytes),
    generationsToKeep: boundedInt("generationsToKeep", merged.generationsToKeep),
    auditMaxFileBytes: boundedInt("auditMaxFileBytes", merged.auditMaxFileBytes),
    auditMaxFiles: boundedInt("auditMaxFiles", merged.auditMaxFiles),
    auditRetentionDays: boundedInt("auditRetentionDays", merged.auditRetentionDays)
  };
}

export function loadConfig(configPath: string): EngbrainConfig {
  const text = readTextFileBounded(configPath, CONFIG_FILE_MAX_BYTES);
  if (text === null) {
    return { ...DEFAULT_CONFIG };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return fail("config.json is not valid JSON");
  }
  return validateConfig(parsed);
}
