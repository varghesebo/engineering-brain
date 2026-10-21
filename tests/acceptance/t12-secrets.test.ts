import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { indexRepository } from "@engbrain/core";
import { afterAll, describe, expect, it } from "vitest";
import { cleanupTempDirs, dumpCurrent, engbrainHome, makeGitRepo, openFor, runCli } from "../helpers/env.js";
import { FAKE_SECRETS } from "../helpers/fixtures.js";

afterAll(cleanupTempDirs);

const SECRET_VALUES = {
  aws: FAKE_SECRETS.awsKey(),
  github: FAKE_SECRETS.githubToken(),
  slack: FAKE_SECRETS.slackToken(),
  dbUrlPassword: "s3cr3tpass",
  literalPassword: "hunter2-correct-horse",
  envValue: "env-file-value-9f8e7d6c5b4a",
  pemBody: "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC"
};

function allStoreBytes(storeDir: string): string {
  return readdirSync(storeDir)
    .map((name) => {
      try {
        return readFileSync(join(storeDir, name)).toString("latin1");
      } catch {
        return "";
      }
    })
    .join("\n");
}

describe("T12 secrets never reach the index, audit log, config or CLI output", () => {
  it("excludes secret-bearing files and stores no secret text anywhere in the store", async () => {
    const home = engbrainHome();
    const repo = makeGitRepo({
      "src/ok.ts": "export const ok = 1;\n",
      "src/aws.ts": `export const k = "${SECRET_VALUES.aws}";\n`,
      "src/gh.ts": `// ${SECRET_VALUES.github}\nexport const g = 1;\n`,
      "src/slack.ts": `export const s = "${SECRET_VALUES.slack}";\n`,
      "src/db.ts": `export const url = "${FAKE_SECRETS.urlCredentials()}";\n`,
      "src/pw.ts": `${FAKE_SECRETS.passwordAssignment()}\n`,
      "src/key.ts": `${FAKE_SECRETS.privateKeyHeader()}\n${SECRET_VALUES.pemBody}\n`,
      ".env": `TOKEN=${SECRET_VALUES.envValue}\n`,
      "keys/server.pem": `${FAKE_SECRETS.privateKeyHeader()}\n${SECRET_VALUES.pemBody}\n`
    });

    const outputs: string[] = [];
    for (const args of [["init"], ["index"], ["status", "--check", "--json"], ["index", "--json"]]) {
      const run = await runCli(repo, args, home);
      expect(run.code, run.stderr).toBe(0);
      outputs.push(run.stdout, run.stderr);
    }

    const opened = await openFor(repo, home);
    const dump = dumpCurrent(opened.store);
    opened.close();
    const included = dump.manifest.filter((m) => m[1] !== null).map((m) => m[0]);
    expect(included).toEqual(["src/ok.ts"]);
    const reasons = Object.fromEntries(dump.manifest.filter((m) => m[1] === null).map((m) => [m[0], m[2]]));
    expect(reasons[".env"]).toBe("sensitive_path");
    expect(reasons["keys/server.pem"]).toBe("sensitive_path");
    for (const secretFile of ["src/aws.ts", "src/gh.ts", "src/slack.ts", "src/db.ts", "src/pw.ts", "src/key.ts"]) {
      expect(reasons[secretFile], secretFile).toMatch(/^secret:/);
    }

    const haystack = [allStoreBytes(join(repo, ".engineering-brain")), ...outputs].join("\n");
    for (const [name, value] of Object.entries(SECRET_VALUES)) {
      expect(haystack.includes(value), `secret "${name}" leaked into the store or CLI output`).toBe(false);
    }
    // sensitive file CONTENT is never read: its hash is absent, only the reason is recorded
    expect(dump.manifest.find((m) => m[0] === ".env")?.[1]).toBeNull();
  });

  it("a file that becomes secret-bearing is excluded on the next index and its facts are swept", async () => {
    const home = engbrainHome();
    const repo = makeGitRepo({ "src/a.ts": "export const a = 1;\n", "src/b.ts": "export const b = 2;\n" });
    const o = await openFor(repo, home, true);
    await indexRepository({ store: o.store, git: o.info, hardenedGit: o.git });
    const { writeFileSync } = await import("node:fs");
    writeFileSync(join(repo, "src", "b.ts"), `export const b = "${SECRET_VALUES.aws}";\n`);
    const second = await indexRepository({ store: o.store, git: o.info, hardenedGit: o.git });
    expect(second.stats.excludedByReason["secret:aws_access_key_id"]).toBe(1);
    expect(allStoreBytes(join(repo, ".engineering-brain")).includes(SECRET_VALUES.aws)).toBe(false);
    o.close();
  });
});
