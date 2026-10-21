import { existsSync, readdirSync, renameSync, rmSync, statSync } from "node:fs";
import { join } from "node:path";
import { appendFileNoFollow } from "./fsSafe.js";
import { sha256Hex } from "./hash.js";

export type AuditValue = string | number | boolean | null | ReadonlyArray<string | number | boolean | null>;
export type AuditFields = Record<string, AuditValue>;

export interface AuditLimits {
  maxFileBytes: number;
  maxFiles: number;
  retentionDays: number;
}

const FORBIDDEN_KEYS = new Set(["content", "source", "snippet", "text", "body", "data", "secret", "match"]);
const MAX_STRING = 200;

/**
 * Local, append-only, content-free audit log. Events carry ids, counts, durations and hashed paths only.
 * Paths are hashed (salted with the install id) because path names can themselves be sensitive.
 * Never uploaded anywhere. Mode 0600; size-based rotation; age-based retention.
 */
export class AuditLog {
  private readonly file: string;

  constructor(
    private readonly dir: string,
    private readonly installId: string,
    private readonly limits: AuditLimits,
    private readonly clock: () => Date = () => new Date()
  ) {
    this.file = join(dir, "audit.log");
    this.pruneExpired();
  }

  hashPath(path: string): string {
    return sha256Hex(`${this.installId}\0${path}`).slice(0, 16);
  }

  record(type: string, fields: AuditFields = {}): void {
    const entry: Record<string, unknown> = { ts: this.clock().toISOString(), type };
    for (const [key, value] of Object.entries(fields)) {
      if (FORBIDDEN_KEYS.has(key.toLowerCase())) {
        throw new Error(`audit field not allowed (content-free log): ${key}`);
      }
      entry[key] = typeof value === "string" ? value.slice(0, MAX_STRING) : value;
    }
    const line = `${JSON.stringify(entry)}\n`;
    this.rotateIfNeeded(Buffer.byteLength(line));
    appendFileNoFollow(this.file, line);
  }

  private rotateIfNeeded(incomingBytes: number): void {
    if (!existsSync(this.file) || statSync(this.file).size + incomingBytes <= this.limits.maxFileBytes) {
      return;
    }
    const oldest = `${this.file}.${this.limits.maxFiles - 1}`;
    rmSync(oldest, { force: true });
    for (let index = this.limits.maxFiles - 2; index >= 1; index -= 1) {
      const from = `${this.file}.${index}`;
      if (existsSync(from)) {
        renameSync(from, `${this.file}.${index + 1}`);
      }
    }
    if (this.limits.maxFiles > 1) {
      renameSync(this.file, `${this.file}.1`);
    } else {
      rmSync(this.file, { force: true });
    }
  }

  private pruneExpired(): void {
    const cutoff = this.clock().getTime() - this.limits.retentionDays * 86_400_000;
    for (const name of readdirSync(this.dir)) {
      if (!/^audit\.log(\.\d+)?$/.test(name)) {
        continue;
      }
      const path = join(this.dir, name);
      if (statSync(path).mtimeMs < cutoff) {
        rmSync(path, { force: true });
      }
    }
  }
}
