import { describe, expect, it } from "vitest";
import { FAKE_SECRETS } from "../../../tests/helpers/fixtures.js";
import { scanForSecrets } from "../src/secretScan.js";

describe("secret scanning foundation", () => {
  it.each([
    ["aws_access_key_id", () => `key = ${FAKE_SECRETS.awsKey()}`],
    ["github_token", () => `token: ${FAKE_SECRETS.githubToken()}`],
    ["private_key_block", () => `${FAKE_SECRETS.privateKeyHeader()}\nabc`],
    ["slack_token", () => `s = "${FAKE_SECRETS.slackToken()}"`],
    ["credential_assignment", () => FAKE_SECRETS.passwordAssignment()],
    ["url_credentials", () => `url = "${FAKE_SECRETS.urlCredentials()}"`]
  ])("detects %s", (id, build) => {
    expect(scanForSecrets(build())).toBe(id);
  });

  it("detects a high-entropy token", () => {
    const token = Array.from({ length: 48 }, (_, i) => "aZ3kQ9xL2mB7vR1tY5uW8cN4pD6fH0jG"[(i * 7) % 32]).join("") + "Xq9Zr2Lm";
    expect(scanForSecrets(`value=${token}`)).toBe("high_entropy_token");
  });

  it("detects a JWT-shaped token", () => {
    const part = (n: number): string => "eyJ" + "abcdefghij".repeat(n);
    expect(scanForSecrets(`Authorization: Bearer ${part(2)}.${part(2)}.${"s".repeat(20)}`)).toBe("jwt");
  });

  it("does not return or expose the matched text", () => {
    const result = scanForSecrets(`k=${FAKE_SECRETS.awsKey()}`);
    expect(result).toBe("aws_access_key_id");
    expect(result).not.toContain(FAKE_SECRETS.awsKey());
  });

  it("does not mistake long paths and URLs for secrets (they would take whole config files out of the index)", () => {
    for (const text of [
      '{"scripts":{"build":"touch /var/folders/x8/tndbq99n4tz3f473ln204p_w0000gy/T/engbrain-marker-AbC123/EXECUTED"}}',
      "cd /Users/someone/Documents/Project/engineering-brain/packages/core/src/adapters && run",
      '"resolved": "https://registry.npmjs.org/@types/node/-/node-22.20.5.tgz"'
    ]) {
      expect(scanForSecrets(text), text).toBeNull();
    }
  });

  it("still detects a high-entropy token that is not path-shaped, including one with a single slash", () => {
    const token = Array.from({ length: 48 }, (_, i) => "aZ3kQ9xL2mB7vR1tY5uW8cN4pD6fH0jG"[(i * 7) % 32]).join("") + "Xq9Zr2Lm";
    expect(scanForSecrets(`value=${token}`)).toBe("high_entropy_token");
    expect(scanForSecrets(`value=${token.slice(0, 30)}/${token.slice(30)}`)).toBe("high_entropy_token");
  });

  it("leaves ordinary code and hex digests alone", () => {
    expect(scanForSecrets("export function add(a: number, b: number) { return a + b; }")).toBeNull();
    expect(scanForSecrets(`const sha = "${"a1b2c3d4".repeat(8)}";`)).toBeNull();
  });

  // Known false negatives are TRACKED, not hidden (see tests/fixtures/secret-scan-known-gaps.md).
  // If the scanner improves and one of these starts matching, update the list and this test together.
  it.each([
    ["short passwords", () => 'const password = "abc123";'],
    ["secret split across concatenation", () => `const k = "${["AK", "IA"].join("")}" + "ABCDEFGHIJKLMNOP";`],
    ["low-entropy long tokens", () => `const t = "${"abcd".repeat(12)}";`],
    ["base64 secret broken over lines", () => `x = "dGhpcyBpcyBh\n bm90IGEgcmVhbCBzZWNyZXQ="`],
    ["base64 secret with two slashes in short segments (looks like a path)", () => ["wJalrXUtnFEM", "I/K7MDENG/bPxRfiCYEXAMPLE", "KEYab12CDef"].join("")]
  ])("KNOWN GAP (not detected): %s", (_name, build) => {
    expect(scanForSecrets(build())).toBeNull();
  });
});

describe("hostile input cannot stall the scanner (regression: unbounded scheme prefix took minutes on 1 MiB)", () => {
  const MB = 1024 * 1024;
  const cases: Array<[string, () => string]> = [
    ["dot-separated flood", () => "a.a.".repeat(MB / 4)],
    ["jwt-prefix run then .eyJ", () => `${"eyJ".repeat((MB - 10) / 3)}.eyJ`],
    ["keyword flood", () => "token".repeat(MB / 5)],
    ["unterminated assignment", () => `password="${"x".repeat(MB - 12)}`],
    ["scheme-and-colon flood", () => "a://b:c".repeat(MB / 7)],
    ["one huge token-shaped run", () => "A1b2".repeat(MB / 4)],
    ["many github-prefixed runs", () => "ghp_".repeat(MB / 4)]
  ];
  it.each(cases)("%s scans in bounded time", (_name, build) => {
    const input = build();
    const started = performance.now();
    scanForSecrets(input);
    expect(performance.now() - started).toBeLessThan(2000);
  });
});
