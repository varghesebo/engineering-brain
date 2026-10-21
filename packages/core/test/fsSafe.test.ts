import { mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { cleanupTempDirs, tempDir } from "../../../tests/helpers/env.js";
import { classifyMountInfo, detectFilesystemKind, readRegularFileBounded } from "../src/fsSafe.js";

afterAll(cleanupTempDirs);

describe("readRegularFileBounded", () => {
  it("reads regular files and reports ns timestamps/inode as strings", () => {
    const dir = tempDir();
    writeFileSync(join(dir, "a.txt"), "hello");
    const result = readRegularFileBounded(join(dir, "a.txt"), 100);
    expect(result.kind).toBe("ok");
    if (result.kind === "ok") {
      expect(result.file.data.toString()).toBe("hello");
      expect(result.file.mtimeNs).toMatch(/^\d+$/);
      expect(result.file.inode).toMatch(/^\d+$/);
    }
  });
  it("reports missing files", () => {
    expect(readRegularFileBounded(join(tempDir(), "nope"), 10)).toEqual({ kind: "missing" });
  });
  it("refuses files over the cap without reading them", () => {
    const dir = tempDir();
    writeFileSync(join(dir, "big"), Buffer.alloc(2048));
    expect(readRegularFileBounded(join(dir, "big"), 1024)).toEqual({ kind: "excluded", reason: "too_large" });
  });
  it("refuses directories", () => {
    const dir = tempDir();
    mkdirSync(join(dir, "d"));
    const result = readRegularFileBounded(join(dir, "d"), 10);
    expect(result.kind === "excluded" || result.kind === "missing").toBe(true);
  });
  it.skipIf(process.platform === "win32")("does not follow a final symlink (O_NOFOLLOW)", () => {
    const dir = tempDir();
    writeFileSync(join(dir, "target"), "secret-outside");
    symlinkSync(join(dir, "target"), join(dir, "link"));
    expect(readRegularFileBounded(join(dir, "link"), 100)).toEqual({ kind: "excluded", reason: "symlink" });
  });
});

describe("filesystem kind detection (best effort)", () => {
  const mountinfo = [
    "20 1 8:1 / / rw - ext4 /dev/sda1 rw",
    "30 20 0:27 / /mnt/share rw - nfs4 server:/export rw",
    "31 30 8:2 / /mnt/share/local rw - ext4 /dev/sdb1 rw",
    "32 20 0:28 / /home/dev rw - fuse.sshfs dev@host:/ rw"
  ].join("\n");
  it("uses the longest matching mount point", () => {
    expect(classifyMountInfo(mountinfo, "/mnt/share/repo")).toBe("network");
    expect(classifyMountInfo(mountinfo, "/mnt/share/local/repo")).toBe("local");
    expect(classifyMountInfo(mountinfo, "/home/dev/project")).toBe("network");
    expect(classifyMountInfo(mountinfo, "/srv/repo")).toBe("local");
  });
  it("returns unknown when nothing matches or input is empty", () => {
    expect(classifyMountInfo("", "/x")).toBe("unknown");
  });
  it("flags UNC paths on Windows and does not guess elsewhere", () => {
    expect(detectFilesystemKind("\\\\server\\share\\repo", "win32")).toBe("network");
    expect(detectFilesystemKind("C:\\repo", "win32")).toBe("unknown");
    expect(detectFilesystemKind("/Users/x/repo", "darwin")).toBe("unknown");
  });
});
