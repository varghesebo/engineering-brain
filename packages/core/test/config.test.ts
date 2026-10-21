import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { cleanupTempDirs, tempDir } from "../../../tests/helpers/env.js";
import { DEFAULT_CONFIG, loadConfig, validateConfig } from "../src/config.js";

afterAll(cleanupTempDirs);

describe("config is untrusted input", () => {
  it("returns defaults when no file exists", () => {
    expect(loadConfig(join(tempDir(), "config.json"))).toEqual(DEFAULT_CONFIG);
  });
  it("accepts additive excludes and bounded caps", () => {
    const config = validateConfig({ exclude: ["docs/**"], maxFileBytes: 2048, generationsToKeep: 5 });
    expect(config.exclude).toEqual(["docs/**"]);
    expect(config.maxFileBytes).toBe(2048);
  });
  it("rejects unknown keys (no hidden knobs, e.g. no command or network settings)", () => {
    for (const key of ["command", "network", "allowNetwork", "runScripts", "offline"]) {
      expect(() => validateConfig({ [key]: true })).toThrow(/unknown config key/);
    }
  });
  it("rejects out-of-range values instead of clamping silently", () => {
    expect(() => validateConfig({ maxFileBytes: 1_000_000_000 })).toThrow(/maxFileBytes/);
    expect(() => validateConfig({ generationsToKeep: 0 })).toThrow(/generationsToKeep/);
    expect(() => validateConfig({ auditRetentionDays: 1.5 })).toThrow(/auditRetentionDays/);
  });
  it("rejects exclude patterns that are absolute, drive-qualified or traverse", () => {
    for (const bad of ["/etc/*", "C:/x", "../x", "a/../b", "", "a\0b"]) {
      expect(() => validateConfig({ exclude: [bad] })).toThrow();
    }
    expect(() => validateConfig({ exclude: new Array(201).fill("a") })).toThrow();
  });
  it("rejects malformed JSON and non-objects", () => {
    const dir = tempDir();
    writeFileSync(join(dir, "config.json"), "{not json");
    expect(() => loadConfig(join(dir, "config.json"))).toThrow(/not valid JSON/);
    expect(() => validateConfig([])).toThrow();
    expect(() => validateConfig(null)).toThrow();
  });
  it("ignores config files above the size cap by treating them as unreadable defaults-free failure", () => {
    const dir = tempDir();
    writeFileSync(join(dir, "config.json"), `{"exclude":["${"a".repeat(70_000)}"]}`);
    expect(loadConfig(join(dir, "config.json"))).toEqual(DEFAULT_CONFIG);
  });
});
