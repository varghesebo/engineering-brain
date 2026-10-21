import { randomUUID } from "node:crypto";
import { closeSync, mkdirSync, openSync, readFileSync, writeSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** Per-user config dir. `ENGBRAIN_HOME` overrides it (used by tests). Never inside a repository. */
export function userConfigDir(env: NodeJS.ProcessEnv = process.env, platform: NodeJS.Platform = process.platform): string {
  const override = env["ENGBRAIN_HOME"];
  if (override !== undefined && override !== "") {
    return override;
  }
  if (platform === "win32") {
    return join(env["APPDATA"] ?? join(homedir(), "AppData", "Roaming"), "engbrain");
  }
  return join(env["XDG_CONFIG_HOME"] ?? join(homedir(), ".config"), "engbrain");
}

/**
 * Random id for this machine/user profile. It never leaves the machine; it salts path hashes in the audit log
 * and proves that a store was created here (a store copied in from elsewhere is refused).
 */
export function getInstallId(env: NodeJS.ProcessEnv = process.env): string {
  const dir = userConfigDir(env);
  const file = join(dir, "install.id");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      const existing = readFileSync(file, "utf8").trim();
      if (UUID.test(existing)) {
        return existing;
      }
    } catch {
      // fall through to create
    }
    try {
      const fd = openSync(file, "wx", 0o600);
      try {
        const id = randomUUID();
        writeSync(fd, `${id}\n`);
        return id;
      } finally {
        closeSync(fd);
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") {
        throw error;
      }
    }
  }
  throw new Error("could not establish install id");
}
