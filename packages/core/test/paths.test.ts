import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { absoluteFromStorePath, collisionKey, isInside, toStorePath } from "../src/paths.js";

describe("toStorePath", () => {
  it("normalises to NFC and keeps case", () => {
    const nfd = "src/Cafe\u0301.ts";
    expect(toStorePath(nfd)).toEqual({ ok: true, path: "src/Caf\u00e9.ts" });
  });
  it("rejects traversal, absolute, drive, NUL and empty components", () => {
    for (const bad of ["", "../x", "a/../b", "/etc/passwd", "C:/x", "a//b", "a/./b", "a\0b"]) {
      expect(toStorePath(bad).ok).toBe(false);
    }
  });
  it("flags Windows reserved names on every platform for portability", () => {
    for (const name of ["con", "NUL.txt", "src/aux.ts", "COM1", "lpt9.md"]) {
      expect(toStorePath(name)).toEqual({ ok: false, reason: "reserved_name" });
    }
    expect(toStorePath("console.ts").ok).toBe(true);
  });
});

describe("collisionKey", () => {
  it("collides on case and unicode normalisation differences", () => {
    expect(collisionKey("src/Readme.md")).toBe(collisionKey("src/README.md"));
    expect(collisionKey("caf\u00e9")).toBe(collisionKey("cafe\u0301"));
  });
});

describe("isInside / absoluteFromStorePath", () => {
  it("detects escapes lexically", () => {
    const root = resolve("/tmp/root");
    expect(isInside(root, resolve(root, "a/b"))).toBe(true);
    expect(isInside(root, root)).toBe(true);
    expect(isInside(root, resolve(root, "../other"))).toBe(false);
    expect(isInside(root, resolve("/tmp/root-sibling"))).toBe(false);
  });
  it("joins store paths under the root", () => {
    expect(absoluteFromStorePath(resolve("/r"), "a/b.ts")).toBe(resolve("/r/a/b.ts"));
  });
});
