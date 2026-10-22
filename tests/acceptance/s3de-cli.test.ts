import { afterAll, describe, expect, it } from "vitest";
import { cleanupTempDirs, engbrainHome, makeGitRepo, runCli } from "../helpers/env.js";

afterAll(cleanupTempDirs);

const NO_OPERATOR = { ENGBRAIN_OPERATOR: "", ENGBRAIN_OPERATOR_TOKEN: "" };

describe("S3D/S3E command line", () => {
  it("lists missing adapters, builds a manifest only for an operator, never decides ELIGIBLE without evidence, and reports what was NOT done", async () => {
    const repo = makeGitRepo({ "src/a.ts": "export const a = 1;\n" });
    const home = engbrainHome();
    expect((await runCli(repo, ["init"], home)).code).toBe(0);
    const boot = await runCli(repo, ["memory", "operator", "add", "root", "--roles", "propose,approve,verify,admin", "--yes", "--json"], home);
    const env = { ENGBRAIN_OPERATOR: "root", ENGBRAIN_OPERATOR_TOKEN: (JSON.parse(boot.stdout) as { token: string }).token };
    await runCli(repo, ["refresh", "--history=backfill"], home);
    const adapters = JSON.parse((await runCli(repo, ["sentinel", "adapters", "--json"], home)).stdout) as { notAvailable: Array<{ technique: string; state: string }> };
    expect(adapters.notAvailable.map((a) => a.technique)).toContain("mutation"); // nothing is registered: every technique is visibly unavailable
    expect(adapters.notAvailable.every((a) => a.state !== "available")).toBe(true);
    const id = (JSON.parse((await runCli(repo, ["sentinel", "plan", "--title", "Add retries", "--scope", "src/", "--profile", "A2", "--json"], home, env)).stdout) as { id: string }).id;
    const anon = await runCli(repo, ["sentinel", "manifest", id], home, NO_OPERATOR);
    expect(anon.code).toBe(3);
    const manifest = await runCli(repo, ["sentinel", "manifest", id, "--json"], home, env);
    expect(manifest.code).toBe(0);
    expect((JSON.parse(manifest.stdout) as { manifest: { sha256: string } }).manifest.sha256).toMatch(/^[0-9a-f]{64}$/);
    const decision = await runCli(repo, ["sentinel", "decide", id, "--json"], home, env);
    expect(decision.code).toBe(1); // not eligible
    expect((JSON.parse(decision.stdout) as { decision: { outcome: string } }).decision.outcome).not.toBe("ELIGIBLE_FOR_APPROVAL");
    const report = await runCli(repo, ["sentinel", "assurance-report", id], home);
    expect(report.code).toBe(0);
    expect(report.stdout).toMatch(/NOT EXECUTED/i);
    expect(report.stdout).toMatch(/NOT CERTIFIED/i);
  });
});
