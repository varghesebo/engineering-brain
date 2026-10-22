import { randomUUID } from "node:crypto";
import type Database from "better-sqlite3";
import { EngbrainError } from "../../errors.js";
import { requireRole, type Actor } from "../../memory/operators.js";
import type { SelfTestResult } from "../execution.js";

/**
 * Sentinel 3D adapter registry. An adapter is a RECORD of an external assurance tool (name, version, licence, platforms, the isolation it needs), never a way to run it: nothing in this module
 * executes anything. A technique with no available adapter for the platform stays visibly `unsupported` or `unregistered`; it is never reported as covered.
 */
export const ADAPTER_TECHNIQUES = ["property", "mutation", "fuzz", "race", "fault_injection", "sast", "auth_boundary", "supply_chain", "formal"] as const;
export type AdapterTechnique = (typeof ADAPTER_TECHNIQUES)[number];
export const ADAPTER_ISOLATIONS = ["none", "sandbox", "container", "vm"] as const;
export type AdapterIsolation = (typeof ADAPTER_ISOLATIONS)[number];
export const ADAPTER_STATUSES = ["available", "unsupported", "disabled"] as const;
export type AdapterStatus = (typeof ADAPTER_STATUSES)[number];

export interface AdapterRow {
  adapter_id: string; technique: AdapterTechnique; tool: string; tool_version: string; license: string; platforms_json: string; isolation: AdapterIsolation; needs_network: 0 | 1;
  status: AdapterStatus; status_reason: string; registered_by: string; at: string;
}

export interface AdapterSpec {
  technique: AdapterTechnique; tool: string; version: string; license: string;
  /** Node `process.platform` values the tool runs on (e.g. `darwin`, `linux`). */
  platforms: string[];
  isolation: AdapterIsolation; needsNetwork: boolean;
  /** Defaults to `available`; anything else needs a reason. */
  status?: AdapterStatus; reason?: string;
}

export interface AdapterStanding { state: "available" | "unsupported" | "unregistered"; reason: string; adapter: AdapterRow | null }

const clock = (now?: Date): Date => now ?? new Date();
const word = (v: string, max: number, what: string): string => {
  const t = v.trim();
  if (!new RegExp(`^[A-Za-z0-9][A-Za-z0-9._+@/-]{0,${max - 1}}$`).test(t)) {
    throw new EngbrainError("POLICY_REFUSED", `${what} must be 1-${max} plain characters (letters, digits, . _ + @ / -)`);
  }
  return t;
};
const reasonText = (v: string | undefined): string => {
  const t = (v ?? "").trim();
  if (t.length > 300 || /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(t)) {
    throw new EngbrainError("POLICY_REFUSED", "a status reason is at most 300 characters without control or invisible formatting characters");
  }
  return t;
};
const checkStatus = (status: AdapterStatus, reason: string): void => {
  if (!ADAPTER_STATUSES.includes(status)) {
    throw new EngbrainError("POLICY_REFUSED", "adapter status must be available, unsupported or disabled");
  }
  if (status !== "available" && reason.length === 0) {
    throw new EngbrainError("POLICY_REFUSED", "an adapter that is not available must say why");
  }
};

function getAdapter(db: Database.Database, adapterId: string): AdapterRow {
  const row = db.prepare("SELECT * FROM sentinel_adapters WHERE adapter_id = ?").get(adapterId) as AdapterRow | undefined;
  if (row === undefined) {
    throw new EngbrainError("INVALID_ROOT", "no such adapter");
  }
  return row;
}

/** Admin only: records an adapter for a technique. The record is immutable except for its status; registering a tool never runs it. */
export function registerAdapter(db: Database.Database, actor: Actor, spec: AdapterSpec, now?: Date): AdapterRow {
  requireRole(actor, "admin");
  if (!ADAPTER_TECHNIQUES.includes(spec.technique)) {
    throw new EngbrainError("POLICY_REFUSED", `technique must be one of: ${ADAPTER_TECHNIQUES.join(", ")}`);
  }
  if (!ADAPTER_ISOLATIONS.includes(spec.isolation)) {
    throw new EngbrainError("POLICY_REFUSED", "isolation must be none, sandbox, container or vm");
  }
  const platforms = [...new Set(spec.platforms.map((p) => word(p, 20, "platform")))].sort();
  if (platforms.length === 0 || platforms.length > 10) {
    throw new EngbrainError("POLICY_REFUSED", "an adapter names 1-10 platforms");
  }
  const status = spec.status ?? "available";
  const reason = reasonText(spec.reason);
  checkStatus(status, reason);
  const tool = word(spec.tool, 80, "tool");
  const version = word(spec.version, 40, "tool version");
  const license = word(spec.license, 60, "license");
  const id = `ad_${randomUUID().replace(/-/g, "").slice(0, 16)}`;
  return db.transaction((): AdapterRow => {
    if (db.prepare("SELECT 1 FROM sentinel_adapters WHERE tool = ? AND tool_version = ?").get(tool, version) !== undefined) {
      throw new EngbrainError("POLICY_REFUSED", `${tool} ${version} is already registered: change its status instead`);
    }
    db.prepare(
      "INSERT INTO sentinel_adapters (adapter_id, technique, tool, tool_version, license, platforms_json, isolation, needs_network, status, status_reason, registered_by, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ).run(id, spec.technique, tool, version, license, JSON.stringify(platforms), spec.isolation, spec.needsNetwork ? 1 : 0, status, reason, actor.id, clock(now).toISOString());
    return getAdapter(db, id);
  }).immediate();
}

/** Admin only: marks an adapter available, unsupported or disabled (anything but available needs a reason). */
export function setAdapterStatus(db: Database.Database, actor: Actor, adapterId: string, status: AdapterStatus, reason?: string): AdapterRow {
  requireRole(actor, "admin");
  const why = reasonText(reason);
  checkStatus(status, why);
  return db.transaction((): AdapterRow => {
    getAdapter(db, adapterId);
    db.prepare("UPDATE sentinel_adapters SET status = ?, status_reason = ? WHERE adapter_id = ?").run(status, why, adapterId);
    return getAdapter(db, adapterId);
  }).immediate();
}

/** Whether a technique has an available adapter on a platform. No adapter at all is `unregistered`; adapters that exist but are not usable here are `unsupported`, with the reason. */
export function adapterStatus(db: Database.Database, technique: AdapterTechnique, platform: string): AdapterStanding {
  if (!ADAPTER_TECHNIQUES.includes(technique)) {
    throw new EngbrainError("POLICY_REFUSED", `technique must be one of: ${ADAPTER_TECHNIQUES.join(", ")}`);
  }
  const rows = db.prepare("SELECT * FROM sentinel_adapters WHERE technique = ? ORDER BY at DESC, adapter_id").all(technique) as AdapterRow[];
  if (rows.length === 0) {
    return { state: "unregistered", reason: `no adapter is registered for ${technique}`, adapter: null };
  }
  const onPlatform = rows.filter((r) => (JSON.parse(r.platforms_json) as string[]).includes(platform));
  const usable = onPlatform.find((r) => r.status === "available");
  if (usable !== undefined) {
    return { state: "available", reason: "", adapter: usable };
  }
  const latest = onPlatform[0];
  if (latest !== undefined) {
    return { state: "unsupported", reason: `${latest.tool} ${latest.tool_version} is ${latest.status}: ${latest.status_reason}`, adapter: latest };
  }
  return { state: "unsupported", reason: `no registered ${technique} adapter supports ${platform}`, adapter: null };
}

/** Every technique that has no available adapter on the platform, with why: these are reported as not covered, never silently skipped. */
export function unsupportedTechniques(db: Database.Database, platform: string): Array<{ technique: AdapterTechnique } & AdapterStanding> {
  return ADAPTER_TECHNIQUES.map((technique) => ({ technique, ...adapterStatus(db, technique, platform) })).filter((s) => s.state !== "available");
}

/**
 * Refuses an adapter whose run could not be confined: one that needs network access (no egress is ever allowed), one that is not available, or one that needs sandbox/container/vm isolation
 * while the sandbox self-test did not verify. This is a precondition check only; it runs nothing.
 */
export function requireIsolation(adapter: AdapterRow, sandbox: SelfTestResult): void {
  if (adapter.needs_network !== 0) {
    throw new EngbrainError("POLICY_REFUSED", `${adapter.tool} needs network access: no egress is ever allowed`);
  }
  if (adapter.status !== "available") {
    throw new EngbrainError("POLICY_REFUSED", `${adapter.tool} ${adapter.tool_version} is ${adapter.status}: ${adapter.status_reason}`);
  }
  if (adapter.isolation !== "none" && !sandbox.verified) {
    throw new EngbrainError("POLICY_REFUSED", `${adapter.tool} needs ${adapter.isolation} isolation and it is not verified here: ${sandbox.detail}`);
  }
}
