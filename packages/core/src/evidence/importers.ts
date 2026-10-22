import { EngbrainError } from "../errors.js";
import { scanForSecrets } from "../secretScan.js";
import { parseXml, walk, type XmlNode } from "./xml.js";

/** `vitest` reads the jest-compatible JSON reporter, `pytest` reads `--junitxml` output, `playwright` reads the JSON reporter. */
export type EvidenceFormat = "junit" | "lcov" | "cobertura" | "sarif" | "jest" | "vitest" | "playwright" | "pytest";
export const EVIDENCE_FORMATS: readonly EvidenceFormat[] = ["junit", "lcov", "cobertura", "sarif", "jest", "vitest", "playwright", "pytest"];
export type Outcome = "passed" | "failed" | "skipped" | "timed_out" | "error";

export interface NormalizedResult { suite: string | null; name: string; file: string | null; outcome: Outcome; durationMs: number | null; message: string | null }
export interface NormalizedCoverage { file: string; testName: string | null; linesFound: number; linesHit: number; hitLines: number[] }
export interface NormalizedFinding { tool: string | null; rule: string | null; level: string | null; file: string | null; line: number | null; message: string | null }
export interface NormalizedEvidence {
  format: EvidenceFormat;
  results: NormalizedResult[];
  coverage: NormalizedCoverage[];
  findings: NormalizedFinding[];
  /** The artifact itself declared more than what could be read, or a count did not add up: results are INCOMPLETE and must not be read as the whole run. */
  partial: boolean;
  warnings: string[];
}

export const IMPORT_LIMITS = { results: 200_000, coverageFiles: 100_000, findings: 100_000, message: 300, name: 300, hitLines: 5000 } as const;

/** Every stored string is untrusted artifact text: control and invisible formatting characters become spaces, it is clipped, and secret-looking text is replaced, never stored. */
const clip = (v: string | undefined | null, max: number): string | null => {
  if (v === undefined || v === null || v === "") {
    return null;
  }
  const text = v.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, " ").trim();
  const clipped = text.length > max ? text.slice(0, max) : text;
  return clipped === "" ? null : scanForSecrets(clipped) !== null ? "[redacted: the text looked like a secret]" : clipped;
};
/** The repository root of the parse in progress (parsing is synchronous): lets absolute paths written by a test runner become repository-relative. */
let activeRoot: string | null = null;
/** Failure text is untrusted and can contain anything a test printed: it is clipped, control characters become spaces, and secret-looking text is replaced, never stored. */
// eslint-disable-next-line no-control-regex
const cleanMessage = (v: string | undefined | null): string | null => {
  const text = clip((v ?? "").replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, " ").replace(/\s+/g, " ").trim(), IMPORT_LIMITS.message);
  return text !== null && scanForSecrets(text) !== null ? "[redacted: the message looked like a secret]" : text;
};
const safeFile = (v: string | undefined | null): string | null => {
  if (v === undefined || v === null || v === "") {
    return null;
  }
  let f = v.replace(/\\/g, "/").replace(/^\.\//, "");
  if (activeRoot !== null && f.startsWith(`${activeRoot}/`)) {
    f = f.slice(activeRoot.length + 1);
  }
  return f.startsWith("/") || /^[A-Za-z]:/.test(f) || f.split("/").includes("..") || f.length > 1024 || /[\p{Cc}]/u.test(f) ? null : f; // only repository-relative paths are kept
};
const num = (v: string | undefined): number | null => (v === undefined || v === "" || !Number.isFinite(Number(v)) ? null : Number(v));
const ms = (seconds: string | undefined): number | null => { const s = num(seconds); return s === null ? null : Math.round(s * 1000); };

export function parseJUnit(text: string): NormalizedEvidence {
  const root = parseXml(text);
  const suites = [...walk(root)].filter((n) => n.name === "testsuite");
  if (root.name !== "testsuite" && root.name !== "testsuites") {
    throw new EngbrainError("POLICY_REFUSED", "not a JUnit document (the root must be testsuite or testsuites)");
  }
  const out: NormalizedEvidence = { format: "junit", results: [], coverage: [], findings: [], partial: false, warnings: [] };
  let declared = 0;
  for (const suite of suites) {
    // a nested suite's testcases are visited once, through the suite that directly contains them
    const direct = suite.children.filter((c) => c.name === "testcase");
    declared += direct.length;
    for (const tc of direct) {
      if (out.results.length >= IMPORT_LIMITS.results) {
        out.partial = true;
        out.warnings.push("result limit reached: the rest of the artifact was not read");
        break;
      }
      const kinds = tc.children.map((c) => c.name);
      const failure = tc.children.find((c) => c.name === "failure");
      const error = tc.children.find((c) => c.name === "error");
      const skipped = tc.children.find((c) => c.name === "skipped");
      const problem = failure ?? error;
      const timeout = problem !== undefined && /time(?:d)?[ -]?out/i.test(`${problem.attrs["type"] ?? ""} ${problem.attrs["message"] ?? ""}`);
      const outcome: Outcome = timeout ? "timed_out" : failure !== undefined ? "failed" : error !== undefined ? "error" : skipped !== undefined ? "skipped" : "passed"; // a failure is never hidden behind a skip
      void kinds;
      out.results.push({
        suite: clip(suite.attrs["name"], IMPORT_LIMITS.name), name: clip(tc.attrs["name"], IMPORT_LIMITS.name) ?? "(unnamed)", file: safeFile(tc.attrs["file"]),
        outcome, durationMs: ms(tc.attrs["time"]), message: cleanMessage(problem?.attrs["message"] ?? problem?.text ?? skipped?.attrs["message"])
      });
    }
    const claimedFailures = (num(suite.attrs["failures"]) ?? 0) + (num(suite.attrs["errors"]) ?? 0);
    const seenFailures = direct.filter((t) => t.children.some((c) => c.name === "failure" || c.name === "error")).length;
    if (claimedFailures > seenFailures && !suite.children.some((c) => c.name === "testsuite")) {
      out.partial = true;
      out.warnings.push(`suite "${(suite.attrs["name"] ?? "").slice(0, 60)}" declares ${claimedFailures} failures or errors but only ${seenFailures} are present: the artifact is incomplete`);
    }
    const claimed = num(suite.attrs["tests"]);
    if (claimed !== null && claimed !== direct.length && !suite.children.some((c) => c.name === "testsuite")) {
      out.partial = true;
      out.warnings.push(`suite "${(suite.attrs["name"] ?? "").slice(0, 60)}" declares ${claimed} tests but contains ${direct.length}: the artifact is incomplete`);
    }
  }
  const rootClaim = root.name === "testsuites" ? num(root.attrs["tests"]) : null;
  if (rootClaim !== null && rootClaim !== out.results.length) {
    out.partial = true;
    out.warnings.push(`the document declares ${rootClaim} tests but ${out.results.length} were read`);
  }
  if (suites.length === 0) {
    out.partial = true;
    out.warnings.push("no testsuite elements were found");
  }
  void declared;
  return out;
}

export function parseLcov(text: string): NormalizedEvidence {
  const out: NormalizedEvidence = { format: "lcov", results: [], coverage: [], findings: [], partial: false, warnings: [] };
  let testName: string | null = null;
  let file: string | null = null;
  let found = 0;
  let hit = 0;
  let lines: number[] = [];
  let sawLf = false;
  for (const raw of text.split(/\r?\n/)) {
    if (raw.startsWith("TN:")) {
      testName = clip(raw.slice(3).trim(), IMPORT_LIMITS.name);
    } else if (raw.startsWith("SF:")) {
      file = safeFile(raw.slice(3).trim());
      found = 0; hit = 0; lines = []; sawLf = false;
    } else if (raw.startsWith("DA:") && file !== null) {
      const [ln, count] = raw.slice(3).split(",");
      const l = Number(ln);
      if (Number.isInteger(l) && l > 0) {
        found += sawLf ? 0 : 1;
        if (Number(count) > 0) {
          hit += sawLf ? 0 : 1;
          if (lines.length < IMPORT_LIMITS.hitLines) {
            lines.push(l);
          }
        }
      }
    } else if (raw.startsWith("LF:")) {
      found = Number(raw.slice(3)) || found; sawLf = true;
    } else if (raw.startsWith("LH:")) {
      hit = Number(raw.slice(3)) || hit; sawLf = true;
    } else if (raw === "end_of_record") {
      if (file !== null && out.coverage.length < IMPORT_LIMITS.coverageFiles) {
        out.coverage.push({ file, testName, linesFound: found, linesHit: hit, hitLines: lines });
      } else if (file === null) {
        out.warnings.push("a record named an unsafe or absolute path and was skipped");
      }
      file = null;
    }
  }
  if (file !== null) {
    out.partial = true;
    out.warnings.push("the last record has no end_of_record: the artifact was cut off");
  }
  if (out.coverage.length === 0) {
    out.partial = true;
    out.warnings.push("no coverage records were found");
  }
  return out;
}

export function parseCobertura(text: string): NormalizedEvidence {
  const root = parseXml(text);
  if (root.name !== "coverage") {
    throw new EngbrainError("POLICY_REFUSED", "not a Cobertura document (the root must be coverage)");
  }
  const out: NormalizedEvidence = { format: "cobertura", results: [], coverage: [], findings: [], partial: false, warnings: [] };
  const byFile = new Map<string, { found: number; hit: number; lines: number[] }>();
  for (const cls of [...walk(root)].filter((n) => n.name === "class")) {
    const file = safeFile(cls.attrs["filename"]);
    if (file === null) {
      out.warnings.push("a class named an unsafe or absolute path and was skipped");
      continue;
    }
    const entry = byFile.get(file) ?? { found: 0, hit: 0, lines: [] };
    for (const line of [...walk(cls)].filter((n) => n.name === "line")) {
      entry.found += 1;
      if ((num(line.attrs["hits"]) ?? 0) > 0) {
        entry.hit += 1;
        const l = num(line.attrs["number"]);
        if (l !== null && entry.lines.length < IMPORT_LIMITS.hitLines) {
          entry.lines.push(l);
        }
      }
    }
    byFile.set(file, entry);
  }
  for (const [file, e] of byFile) {
    if (out.coverage.length < IMPORT_LIMITS.coverageFiles) {
      out.coverage.push({ file, testName: null, linesFound: e.found, linesHit: e.hit, hitLines: e.lines });
    }
  }
  if (out.coverage.length === 0) {
    out.partial = true;
    out.warnings.push("no class coverage was found");
  }
  return out;
}

export function parseSarif(text: string): NormalizedEvidence {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    throw new EngbrainError("POLICY_REFUSED", "not valid JSON");
  }
  const runs = (doc as { runs?: unknown })?.runs;
  if (!Array.isArray(runs)) {
    throw new EngbrainError("POLICY_REFUSED", "not a SARIF document (no runs array)");
  }
  const out: NormalizedEvidence = { format: "sarif", results: [], coverage: [], findings: [], partial: false, warnings: [] };
  for (const run of runs as Array<Record<string, any>>) {
    const tool = clip(String(run?.["tool"]?.["driver"]?.["name"] ?? ""), 80);
    for (const r of Array.isArray(run?.["results"]) ? (run["results"] as Array<Record<string, any>>) : []) {
      if (out.findings.length >= IMPORT_LIMITS.findings) {
        out.partial = true;
        out.warnings.push("finding limit reached");
        break;
      }
      const loc = r?.["locations"]?.[0]?.["physicalLocation"];
      out.findings.push({
        tool, rule: clip(String(r?.["ruleId"] ?? ""), 120), level: clip(String(r?.["level"] ?? "warning"), 20), file: safeFile(typeof loc?.["artifactLocation"]?.["uri"] === "string" ? String(loc["artifactLocation"]["uri"]).replace(/^file:\/\//, "") : null),
        line: Number.isInteger(loc?.["region"]?.["startLine"]) ? Number(loc["region"]["startLine"]) : null, message: cleanMessage(String(r?.["message"]?.["text"] ?? ""))
      });
    }
  }
  return out;
}

/** The JSON shape `jest --json` / vitest's jest-compatible reporter write: testResults[].assertionResults[]. */
export function parseJest(text: string): NormalizedEvidence {
  let doc: Record<string, any>;
  try {
    doc = JSON.parse(text) as Record<string, any>;
  } catch {
    throw new EngbrainError("POLICY_REFUSED", "not valid JSON");
  }
  if (!Array.isArray(doc?.["testResults"])) {
    throw new EngbrainError("POLICY_REFUSED", "not a jest-style JSON report (no testResults array)");
  }
  const out: NormalizedEvidence = { format: "jest", results: [], coverage: [], findings: [], partial: false, warnings: [] };
  for (const file of doc["testResults"] as Array<Record<string, any>>) {
    const path = safeFile(typeof file?.["name"] === "string" ? String(file["name"]) : null);
    if (file?.["status"] === "failed" && (!Array.isArray(file?.["assertionResults"]) || file["assertionResults"].length === 0)) {
      out.partial = true;
      out.warnings.push("a test file failed to run (no assertion results): the run is incomplete");
    }
    for (const a of Array.isArray(file?.["assertionResults"]) ? (file["assertionResults"] as Array<Record<string, any>>) : []) {
      if (out.results.length >= IMPORT_LIMITS.results) {
        out.partial = true;
        out.warnings.push("result limit reached");
        break;
      }
      const status = String(a?.["status"] ?? "");
      const message = Array.isArray(a?.["failureMessages"]) ? String(a["failureMessages"][0] ?? "") : "";
      out.results.push({
        suite: clip(Array.isArray(a?.["ancestorTitles"]) ? (a["ancestorTitles"] as unknown[]).join(" > ") : null, IMPORT_LIMITS.name), name: clip(String(a?.["title"] ?? a?.["fullName"] ?? ""), IMPORT_LIMITS.name) ?? "(unnamed)", file: path,
        outcome: status === "passed" ? "passed" : status === "failed" ? (/time(?:d)?[ -]?out/i.test(message) ? "timed_out" : "failed") : status === "pending" || status === "skipped" || status === "todo" ? "skipped" : "error",
        durationMs: Number.isFinite(a?.["duration"]) ? Math.round(Number(a["duration"])) : null, message: cleanMessage(message)
      });
    }
  }
  const failedRows = out.results.filter((r) => r.outcome === "failed" || r.outcome === "timed_out" || r.outcome === "error").length;
  if ((Number(doc["numFailedTests"] ?? 0) > failedRows || (doc["numTotalTests"] !== undefined && Number(doc["numTotalTests"]) !== out.results.length)) && !out.partial) {
    out.partial = true;
    out.warnings.push("the report's totals disagree with the results it lists: the artifact is incomplete or altered");
  }
  if (Number(doc["numFailedTestSuites"] ?? 0) > 0 && !out.partial) {
    out.partial = true;
    out.warnings.push(`${Number(doc["numFailedTestSuites"])} test suites failed to run`);
  }
  if (out.results.length === 0) {
    out.partial = true;
    out.warnings.push("no assertion results were found");
  }
  return out;
}

export function parseEvidence(format: EvidenceFormat, text: string, options: { repoRoot?: string } = {}): NormalizedEvidence {
  activeRoot = options.repoRoot === undefined ? null : options.repoRoot.replace(/\\/g, "/").replace(/\/+$/, "");
  try {
    return parseByFormat(format, text);
  } finally {
    activeRoot = null;
  }
}

function parseByFormat(format: EvidenceFormat, text: string): NormalizedEvidence {
  switch (format) {
    case "junit": return parseJUnit(text);
    case "lcov": return parseLcov(text);
    case "cobertura": return parseCobertura(text);
    case "sarif": return parseSarif(text);
    case "jest": return parseJest(text);
    case "vitest": return { ...parseJest(text), format: "vitest" };
    case "pytest": return { ...parseJUnit(text), format: "pytest" };
    case "playwright": return parsePlaywright(text);
  }
}

/**
 * Playwright's JSON reporter. The outcome is the LAST attempt's result, except that a test that only passed after retrying (`flaky`) is recorded as failed: a flaky pass must never read as green.
 * `interrupted` and a missing result are recorded as errors, and an interrupted run marks the whole artifact partial.
 */
export function parsePlaywright(text: string): NormalizedEvidence {
  let doc: Record<string, any>;
  try {
    doc = JSON.parse(text) as Record<string, any>;
  } catch {
    throw new EngbrainError("POLICY_REFUSED", "not valid JSON");
  }
  if (!Array.isArray(doc?.["suites"])) {
    throw new EngbrainError("POLICY_REFUSED", "not a Playwright JSON report (no suites array)");
  }
  const out: NormalizedEvidence = { format: "playwright", results: [], coverage: [], findings: [], partial: false, warnings: [] };
  const visit = (suite: Record<string, any>, ancestors: string[], depth: number): void => {
    if (depth > 32) {
      out.partial = true;
      out.warnings.push("suite nesting too deep: the rest was not read");
      return;
    }
    const titles = [...ancestors, ...(typeof suite?.["title"] === "string" && suite["title"] !== "" ? [String(suite["title"])] : [])];
    for (const spec of Array.isArray(suite?.["specs"]) ? (suite["specs"] as Array<Record<string, any>>) : []) {
      for (const test of Array.isArray(spec?.["tests"]) ? (spec["tests"] as Array<Record<string, any>>) : []) {
        if (out.results.length >= IMPORT_LIMITS.results) {
          out.partial = true;
          out.warnings.push("result limit reached");
          return;
        }
        const results = Array.isArray(test?.["results"]) ? (test["results"] as Array<Record<string, any>>) : [];
        const last = results[results.length - 1];
        const status = String(last?.["status"] ?? "");
        const flaky = test?.["status"] === "flaky";
        const outcome: Outcome = flaky ? "failed" : status === "passed" ? "passed" : status === "failed" ? "failed" : status === "timedOut" ? "timed_out" : status === "skipped" ? "skipped" : "error";
        if (status === "interrupted" || last === undefined) {
          out.partial = true;
        }
        out.results.push({
          suite: clip(titles.join(" > "), IMPORT_LIMITS.name), name: clip(String(spec?.["title"] ?? ""), IMPORT_LIMITS.name) ?? "(unnamed)", file: safeFile(typeof spec?.["file"] === "string" ? spec["file"] : typeof suite?.["file"] === "string" ? suite["file"] : null),
          outcome, durationMs: last !== undefined && Number.isFinite(last["duration"]) ? Math.round(Number(last["duration"])) : null, message: cleanMessage(flaky ? "flaky: passed only after retrying" : String(last?.["error"]?.["message"] ?? ""))
        });
      }
    }
    for (const child of Array.isArray(suite?.["suites"]) ? (suite["suites"] as Array<Record<string, any>>) : []) {
      visit(child, titles, depth + 1);
    }
  };
  for (const suite of doc["suites"] as Array<Record<string, any>>) {
    visit(suite, [], 0);
  }
  const reportedErrors = Array.isArray(doc["errors"]) ? (doc["errors"] as unknown[]).length : 0;
  if (reportedErrors > 0) {
    out.partial = true;
    out.warnings.push(`the report lists ${reportedErrors} global errors: the run is incomplete`);
  }
  const stats = doc["stats"] as Record<string, unknown> | undefined;
  if (stats !== undefined && Number(stats["unexpected"] ?? 0) > out.results.filter((r) => r.outcome === "failed" || r.outcome === "timed_out" || r.outcome === "error").length) {
    out.partial = true;
    out.warnings.push("the report's failure count is higher than the failures it lists");
  }
  if (out.results.length === 0) {
    out.partial = true;
    out.warnings.push("no test results were found");
  }
  return out;
}

export type { XmlNode };
