import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { FAKE_SECRETS } from "../../../tests/helpers/fixtures.js";
import { EngbrainError } from "../src/errors.js";
import { parseAssurance } from "../src/evidence/assuranceParsers.js";
import { parseEvidence, type EvidenceFormat } from "../src/evidence/importers.js";

const fixture = (name: string): string => readFileSync(fileURLToPath(new URL(`../../../tests/fixtures/sentinel3d/${name}`, import.meta.url)), "utf8");
const parse = (format: EvidenceFormat, doc: unknown): ReturnType<typeof parseAssurance> => parseAssurance(format, JSON.stringify(doc));
const SHA = "a".repeat(64);
const ASSURANCE: EvidenceFormat[] = ["stryker", "fastcheck", "hypothesis", "semgrep_json", "tla", "z3", "race_log"];
const hostile = `evil\u0000\u001b[31m\u202e\u200btext\u2028line`;

/** Every string anywhere in the parse output, for blanket hygiene assertions. */
function strings(v: unknown, acc: string[] = []): string[] {
  if (typeof v === "string") {
    acc.push(v);
  } else if (Array.isArray(v)) {
    v.forEach((x) => strings(x, acc));
  } else if (typeof v === "object" && v !== null) {
    Object.entries(v).forEach(([k, x]) => { acc.push(k); strings(x, acc); });
  }
  return acc;
}
const expectClean = (v: unknown): void => {
  for (const s of strings(v)) {
    expect(s).not.toMatch(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u);
  }
};

describe("parseAssurance: common input handling", () => {
  it.each(ASSURANCE)("%s refuses invalid JSON", (format) => {
    expect(() => parseAssurance(format, "{not json")).toThrow(EngbrainError);
    expect(() => parseAssurance(format, "{not json")).toThrow(/not valid JSON/);
  });

  it.each(ASSURANCE)("%s refuses a non-object root", (format) => {
    for (const text of ["[]", "null", "42", "\"x\""]) {
      expect(() => parseAssurance(format, text)).toThrow(/must be a JSON object/);
    }
  });

  it.each(ASSURANCE)("%s refuses a wrong shape", (format) => {
    expect(() => parse(format, { unrelated: true })).toThrow(EngbrainError);
  });

  it("refuses an oversized artifact before parsing it", () => {
    expect(() => parseAssurance("race_log", " ".repeat(20 * 1024 * 1024 + 1))).toThrow(/larger than/);
  });

  it("refuses a non-assurance format", () => {
    expect(() => parseAssurance("junit", "{}")).toThrow(/not an assurance format/);
  });

  it("is reached through parseEvidence", () => {
    const out = parseEvidence("race_log", fixture("race-lost-update.json"));
    expect(out.format).toBe("race_log");
    expect(out.assurance?.kind).toBe("race");
  });
});

describe("stryker", () => {
  it("parses a report with one survivor", () => {
    const out = parseAssurance("stryker", fixture("stryker-survivor.json"));
    expect(out.partial).toBe(false);
    expect(out.assurance).toMatchObject({ kind: "mutation", tool: "stryker", toolVersion: "8.2.6" });
    const mutants = out.assurance?.mutants ?? [];
    expect(mutants).toHaveLength(4);
    expect(mutants.filter((m) => m.status === "survived")).toEqual([{ key: "src/auth/guard.ts#1", file: "src/auth/guard.ts", line: 2, mutator: "LogicalOperator", status: "survived" }]);
    expect(mutants.filter((m) => m.status === "killed")).toHaveLength(3);
    expect(out.results.map((r) => r.outcome).sort()).toEqual(["failed", "passed", "passed", "passed"]);
    expect(out.results.find((r) => r.outcome === "failed")).toMatchObject({ file: "src/auth/guard.ts", name: "LogicalOperator #1 at line 2" });
  });

  it("parses an all-killed report", () => {
    const out = parseAssurance("stryker", fixture("stryker-all-killed.json"));
    expect(out.partial).toBe(false);
    expect(out.assurance?.mutants?.every((m) => m.status === "killed")).toBe(true);
    expect(out.results.every((r) => r.outcome === "passed")).toBe(true);
  });

  it("maps every Stryker status", () => {
    const statuses = ["Killed", "Survived", "NoCoverage", "Timeout", "RuntimeError", "CompileError", "Ignored", "Pending"];
    const out = parse("stryker", { files: { "a.ts": { mutants: statuses.map((status, i) => ({ id: i, mutatorName: "M", status, location: { start: { line: i + 1 } } })) } } });
    expect(out.assurance?.mutants?.map((m) => m.status)).toEqual(["killed", "survived", "survived", "inconclusive", "inconclusive", "inconclusive", "inconclusive", "inconclusive"]);
    expect(out.results.map((r) => r.outcome)).toEqual(["passed", "failed", "failed", "skipped", "skipped", "skipped", "skipped", "skipped"]);
    expect(out.warnings).toEqual([]);
  });

  it("records an unknown status as inconclusive with a warning", () => {
    const out = parse("stryker", { files: { "a.ts": { mutants: [{ id: "1", status: "Vanished" }, { id: "2", status: "constructor" }] } } });
    expect(out.assurance?.mutants?.map((m) => m.status)).toEqual(["inconclusive", "inconclusive"]);
    expect(out.warnings.join(" ")).toMatch(/unknown status/);
    expect(out.warnings).toHaveLength(1);
  });

  it("skips unsafe paths and malformed entries as partial", () => {
    const out = parse("stryker", { files: {
      "/etc/passwd": { mutants: [{ id: "1", status: "Killed" }] },
      "../outside.ts": { mutants: [{ id: "1", status: "Killed" }] },
      "C:/win.ts": { mutants: [{ id: "1", status: "Killed" }] },
      "ok.ts": { mutants: [42, { id: "1", status: "Killed", location: { start: { line: -3 } } }] },
      "no-list.ts": {}
    } });
    expect(out.partial).toBe(true);
    expect(out.assurance?.mutants).toEqual([{ key: "ok.ts#1", file: "ok.ts", line: null, mutator: null, status: "killed" }]);
  });

  it("marks an empty report partial", () => {
    const out = parse("stryker", { files: {} });
    expect(out.partial).toBe(true);
    expect(out.warnings).toContain("no mutants were found");
  });

  it("refuses a report whose files is not an object", () => {
    expect(() => parse("stryker", { files: [] })).toThrow(/no files object/);
  });

  it("cleans and redacts hostile strings", () => {
    const out = parse("stryker", { framework: { version: hostile }, files: { "src/x.ts": { mutants: [{ id: FAKE_SECRETS.githubToken(), mutatorName: hostile, status: "Survived" }] } } });
    expectClean(out);
    expect(JSON.stringify(out)).not.toContain(FAKE_SECRETS.githubToken());
    expect(out.assurance?.mutants?.[0]?.mutator).toBe("evil [31m text line");
  });
});

describe("fastcheck", () => {
  it("parses a shrunk counterexample", () => {
    const out = parseAssurance("fastcheck", fixture("fastcheck-shrunk.json"));
    expect(out.partial).toBe(false);
    const p = out.assurance?.property;
    expect(out.assurance).toMatchObject({ kind: "property", tool: "fast-check", toolVersion: "3.22.0" });
    expect(p).toMatchObject({ seed: "1729314157", numRuns: 100, failed: true, shrunk: "[[0,-1]]", shrinkSteps: 8 });
    expect((JSON.parse(p?.counterexample ?? "null") as number[][])[0]).toHaveLength(40);
    expect(p?.shrinkSteps).toBeGreaterThan(0);
    expect(out.results).toHaveLength(1);
    expect(out.results[0]).toMatchObject({ outcome: "failed", name: "sortedInsert keeps the array sorted" });
    expect(out.results[0]?.message).toContain("[[0,-1]]");
  });

  it("derives shrink steps from the shrink path", () => {
    const out = parse("fastcheck", { seed: 1, numRuns: 10, failed: true, counterexample: [1], shrinkPath: "3:0:1" });
    expect(out.assurance?.property?.shrinkSteps).toBe(2);
    expect(parse("fastcheck", { seed: 1, numRuns: 10, failed: true, counterexample: [1], shrinkPath: "3:x" }).assurance?.property?.shrinkSteps).toBeNull();
  });

  it("records a passing property", () => {
    const out = parse("fastcheck", { seed: "42", numRuns: 1000, failed: false, counterexample: null });
    expect(out.partial).toBe(false);
    expect(out.results[0]?.outcome).toBe("passed");
    expect(out.assurance?.tool).toBe("fast-check");
  });

  it("is partial when the seed, run count or counterexample is missing", () => {
    const out = parse("fastcheck", { failed: true });
    expect(out.partial).toBe(true);
    expect(out.warnings.join(" ")).toMatch(/no seed/);
    expect(out.warnings.join(" ")).toMatch(/how many runs/);
    expect(out.warnings.join(" ")).toMatch(/no counterexample/);
  });

  it("refuses a non-boolean failed", () => {
    expect(() => parse("fastcheck", { seed: 1, numRuns: 1, failed: "yes" })).toThrow(/failed/);
  });

  it("bounds a huge or deep counterexample", () => {
    let deep: unknown = 0;
    for (let i = 0; i < 100; i += 1) {
      deep = [deep];
    }
    const out = parse("fastcheck", { seed: 1, numRuns: 1, failed: true, counterexample: deep, shrunk: Array.from({ length: 50_000 }, (_, i) => i) });
    expect(out.partial).toBe(true);
    expect(out.warnings.join(" ")).toMatch(/truncated/);
    expect((out.assurance?.property?.shrunk ?? "").length).toBeLessThanOrEqual(2000);
  });

  it("redacts a secret-looking counterexample", () => {
    const out = parse("fastcheck", { seed: 1, numRuns: 1, failed: true, counterexample: { k: FAKE_SECRETS.awsKey() } });
    expect(out.assurance?.property?.counterexample).toMatch(/redacted/);
    expect(JSON.stringify(out)).not.toContain(FAKE_SECRETS.awsKey());
  });
});

describe("hypothesis", () => {
  it("parses the documented wrapper", () => {
    const out = parse("hypothesis", { test: "tests/test_sort.py::test_sorted", seed: 12345, failed: true, falsifying_example: "xs=[0, -1]", shrink_steps: 14 });
    expect(out.partial).toBe(false);
    expect(out.assurance).toMatchObject({ kind: "property", tool: "hypothesis" });
    expect(out.assurance?.property).toEqual({ seed: "12345", numRuns: null, failed: true, counterexample: "xs=[0, -1]", shrunk: "xs=[0, -1]", shrinkSteps: 14 });
    expect(out.results[0]).toMatchObject({ name: "tests/test_sort.py::test_sorted", outcome: "failed" });
  });

  it("is partial without a test name, seed or example", () => {
    const out = parse("hypothesis", { failed: true });
    expect(out.partial).toBe(true);
    expect(out.results[0]?.name).toBe("(unnamed property)");
  });

  it("refuses raw pytest text", () => {
    expect(() => parseAssurance("hypothesis", "Falsifying example: test_sorted(xs=[0, -1])")).toThrow(/not valid JSON/);
  });
});

describe("semgrep_json", () => {
  it("parses the planted auth bypass", () => {
    const out = parseAssurance("semgrep_json", fixture("semgrep-auth-bypass.json"));
    expect(out.partial).toBe(false);
    expect(out.assurance).toEqual({ kind: "sast", tool: "semgrep", toolVersion: "1.85.0" });
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0]).toMatchObject({ tool: "semgrep", rule: "sentinel.auth.always-true-admin-check", level: "error", file: "src/auth/guard.ts", line: 14 });
    expect(out.findings[0]?.message).toContain("if (user.isAdmin || true)");
  });

  it("maps severities and flags unknown ones", () => {
    const r = (severity: unknown): unknown => ({ check_id: "r", path: "a.ts", start: { line: 1 }, extra: { severity, message: "m" } });
    const out = parse("semgrep_json", { results: [r("ERROR"), r("WARNING"), r("INFO"), r("BOGUS"), r(undefined)] });
    expect(out.findings.map((f) => f.level)).toEqual(["error", "warning", "note", "warning", "warning"]);
    expect(out.warnings.join(" ")).toMatch(/unknown severity/);
  });

  it("is partial when the scan reported errors", () => {
    const out = parse("semgrep_json", { results: [], errors: [{ message: "parse error" }] });
    expect(out.partial).toBe(true);
    expect(out.findings).toEqual([]);
  });

  it("treats an empty clean scan as complete", () => {
    expect(parse("semgrep_json", { results: [], errors: [] }).partial).toBe(false);
  });

  it("drops unsafe paths and cleans hostile text", () => {
    const out = parse("semgrep_json", { results: [
      { check_id: hostile, path: "/abs/x.ts", start: { line: 2 }, extra: { severity: "ERROR", message: `${hostile} ${FAKE_SECRETS.passwordAssignment()}` } },
      { check_id: "r", path: "a/../../b.ts", extra: {} },
      "not an object"
    ] });
    expect(out.findings.map((f) => f.file)).toEqual([null, null]);
    expect(out.findings[0]?.message).toMatch(/redacted/);
    expect(out.partial).toBe(true);
    expectClean(out);
  });
});

describe("tla and z3", () => {
  it("parses a TLA+ counterexample with its trace", () => {
    const out = parseAssurance("tla", fixture("tla-counterexample.json"));
    expect(out.partial).toBe(false);
    expect(out.assurance).toMatchObject({ kind: "formal", tool: "TLC", toolVersion: "2.18" });
    expect(out.assurance?.formal).toMatchObject({ result: "counterexample", specVersion: "TokenBucket-v3" });
    expect(out.assurance?.formal?.modelSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(out.assurance?.formal?.counterexample).toHaveLength(3);
    expect(out.results[0]?.outcome).toBe("failed");
  });

  it("records z3 unsat of the negated invariant as a scoped success only", () => {
    const out = parseAssurance("z3", fixture("z3-unsat-scoped.json"));
    expect(out.partial).toBe(false);
    expect(out.assurance?.formal).toMatchObject({ result: "scoped_success", counterexample: null });
    expect(out.results[0]?.outcome).toBe("passed");
    expect(out.results[0]?.message).toMatch(/scoped success/);
    expect(out.results[0]?.message).toMatch(/not a proof about the application/);
    expect(JSON.stringify(out)).not.toMatch(/\bproven\b|\bverified\b|application-wide/i);
  });

  it("maps z3 sat to a counterexample and needs a trace", () => {
    const base = { tool: "z3", version: "4.13.0", specVersion: "v1", modelSha256: SHA };
    const withTrace = parse("z3", { ...base, result: "sat", trace: { x: 3 } });
    expect(withTrace.assurance?.formal).toMatchObject({ result: "counterexample", counterexample: { x: 3 } });
    expect(withTrace.partial).toBe(false);
    const without = parse("z3", { ...base, result: "sat" });
    expect(without.partial).toBe(true);
    expect(without.warnings.join(" ")).toMatch(/without a trace/);
  });

  it("maps unknown and error results to no conclusion", () => {
    const base = { tool: "TLC", version: "2.18", specVersion: "v1", modelSha256: SHA };
    expect(parse("tla", { ...base, result: "unknown" }).results[0]?.outcome).toBe("skipped");
    expect(parse("tla", { ...base, result: "error" }).results[0]?.outcome).toBe("error");
  });

  it("refuses sat/unsat for TLA+ and unknown result words", () => {
    expect(() => parse("tla", { result: "unsat" })).toThrow(/result must be/);
    expect(() => parse("z3", { result: "proved" })).toThrow(/result must be/);
  });

  it("is partial when provenance is missing or the digest is malformed", () => {
    const out = parse("z3", { result: "unsat", modelSha256: "not-a-digest" });
    expect(out.partial).toBe(true);
    expect(out.assurance?.formal?.modelSha256).toBeNull();
    expect(out.warnings.join(" ")).toMatch(/hex digest/);
    expect(out.warnings.join(" ")).toMatch(/specVersion/);
    expect(out.warnings.join(" ")).toMatch(/tool and its version/);
  });

  it("sanitizes a hostile trace without touching prototypes", () => {
    const text = `{"tool":"TLC","version":"1","specVersion":"v","modelSha256":"${SHA}","result":"counterexample","trace":{"__proto__":{"polluted":true},"k\\u0000":"${hostile.replace(/[\u0000-\u001f\u2028\u202e\u200b]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`)}"}}`;
    const out = parseAssurance("tla", text);
    expectClean(out);
    expect(({} as Record<string, unknown>)["polluted"]).toBeUndefined();
    expect(Object.hasOwn(out.assurance?.formal?.counterexample as object, "__proto__")).toBe(true);
  });
});

describe("race_log", () => {
  it("parses the lost-update schedule", () => {
    const out = parseAssurance("race_log", fixture("race-lost-update.json"));
    expect(out.partial).toBe(false);
    expect(out.assurance).toMatchObject({ kind: "race", tool: "sentinel-race-harness", toolVersion: "0.1.0" });
    expect(out.assurance?.race?.seed).toBe("7");
    expect(out.assurance?.race?.schedule).toHaveLength(4);
    expect(out.assurance?.race?.violation).toMatch(/lost update/);
    expect(out.results).toEqual([expect.objectContaining({ name: "race schedule (seed 7)", outcome: "failed" })]);
  });

  it("records a clean schedule as passed", () => {
    const out = parse("race_log", { tool: "h", seed: 1, schedule: ["a"], violation: null });
    expect(out.results[0]?.outcome).toBe("passed");
    expect(out.assurance?.race?.violation).toBeNull();
  });

  it("refuses a wrong schedule or violation shape", () => {
    expect(() => parse("race_log", { tool: "h", seed: 1, schedule: [1], violation: null })).toThrow(/schedule/);
    expect(() => parse("race_log", { tool: "h", seed: 1, schedule: [], violation: 3 })).toThrow(/violation/);
    expect(() => parse("race_log", { tool: "h", seed: 1, schedule: [] })).toThrow(/violation/);
  });

  it("caps an oversized schedule as partial", () => {
    const out = parse("race_log", { tool: "h", seed: 1, schedule: Array.from({ length: 10_050 }, (_, i) => `s${i}`), violation: null });
    expect(out.partial).toBe(true);
    expect(out.assurance?.race?.schedule).toHaveLength(10_000);
  });

  it("is partial without a seed or tool, and cleans hostile steps", () => {
    const out = parse("race_log", { schedule: [hostile, ""], violation: FAKE_SECRETS.slackToken() });
    expect(out.partial).toBe(true);
    expect(out.assurance?.race?.schedule).toEqual(["evil [31m text line", "(empty step)"]);
    expect(out.assurance?.race?.violation).toMatch(/redacted/);
    expectClean(out);
  });
});
