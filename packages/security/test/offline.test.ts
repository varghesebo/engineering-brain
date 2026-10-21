import dns from "node:dns";
import net from "node:net";
import { describe, expect, it } from "vitest";
import { installNetworkGuard } from "../src/networkGuard.js";
import { authorizeOperation, checkIsolation } from "../src/offline.js";

describe("offline policy (fail closed)", () => {
  it("allows in-process and hardened-git operations", () => {
    expect(authorizeOperation("in-process")).toEqual({ allowed: true });
    expect(authorizeOperation("hardened-git")).toEqual({ allowed: true });
  });

  it("refuses repo-influenced children and test execution: no verified isolation exists in this build", () => {
    expect(checkIsolation()).toMatchObject({ available: false, verified: false, mechanism: null });
    for (const op of ["repo-influenced-child", "repo-test-execution"] as const) {
      const result = authorizeOperation(op);
      expect(result.allowed).toBe(false);
      expect(result).toMatchObject({ code: "ISOLATION_UNAVAILABLE" });
    }
  });

  it("refuses when isolation is claimed available but NOT verified by a self-test", () => {
    const broken = () => ({ available: true, verified: false, mechanism: "fake", reason: "probe not run" });
    expect(authorizeOperation("repo-test-execution", broken).allowed).toBe(false);
  });

  it("refuses when verification passed but isolation is unavailable", () => {
    const odd = () => ({ available: false, verified: true, mechanism: "fake", reason: "inconsistent" });
    expect(authorizeOperation("repo-influenced-child", odd).allowed).toBe(false);
  });

  it("allows only when isolation is available AND verified", () => {
    const good = () => ({ available: true, verified: true, mechanism: "test-double", reason: "ok" });
    expect(authorizeOperation("repo-test-execution", good)).toEqual({ allowed: true });
  });
});

describe("network guard (test instrument)", () => {
  it("records and blocks attempts, and restores originals on uninstall", () => {
    const originalConnect = net.connect;
    const originalLookup = dns.lookup;
    const guard = installNetworkGuard();
    try {
      expect(() => net.connect({ port: 9, host: "127.0.0.1" })).toThrow(/blocked/);
      expect(() => dns.lookup("example.invalid", () => undefined)).toThrow(/blocked/);
      expect(guard.attempts.map((a) => a.api)).toEqual(expect.arrayContaining(["net.connect", "dns.lookup"]));
    } finally {
      guard.uninstall();
    }
    expect(net.connect).toBe(originalConnect);
    expect(dns.lookup).toBe(originalLookup);
  });
});
