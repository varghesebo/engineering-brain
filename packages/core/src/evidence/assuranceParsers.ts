import { EngbrainError } from "../errors.js";
import { scanForSecrets } from "../secretScan.js";
import type { AssuranceDetail, MutantRecord } from "./assuranceTypes.js";
import { IMPORT_LIMITS, type EvidenceFormat, type NormalizedEvidence, type NormalizedResult, type Outcome } from "./importers.js";

/**
 * Pure parsers for adversarial-assurance artifacts. Every input is untrusted: invalid JSON or a wrong top-level shape throws, a
 * truncated or over-limit artifact is returned `partial` with a warning, and every stored string is cleaned, clipped and secret-scanned.
 * Accepted shapes:
 *   stryker      mutation-testing-report-schema JSON: `files: { [path]: { mutants: [{ id, mutatorName, status, location: { start: { line } } }] } }`.
 *   fastcheck    wrapper `{ tool?, version?, property?, seed, numRuns, failed, counterexample, shrunk?, shrinkSteps? | shrinkPath? }` (`shrinkPath` is fast-check's "run:step:step" path).
 *   hypothesis   wrapper `{ tool?, version?, test, seed, failed, falsifying_example?, shrink_steps? }` written by the caller; raw pytest/Hypothesis text output is NOT parsed.
 *   semgrep_json Semgrep `--json` output: `results[]` with `check_id`, `path`, `start.line`, `extra.severity`, `extra.message`; a non-empty `errors[]` marks the scan partial.
 *   tla, z3      wrapper `{ tool, version, specVersion, modelSha256, result, trace? }`. For z3 the solver is given the NEGATED invariant: `unsat` means no violation within the model (a
 *                scoped success), `sat` means a counterexample. A success is only ever scoped to the model and its bounds: nothing here records an application-wide proof.
 *   race_log     wrapper `{ tool, seed, schedule: string[], violation: string | null }`.
 */
type AssuranceFormat = "stryker" | "fastcheck" | "hypothesis" | "semgrep_json" | "tla" | "z3" | "race_log";

/** Limits beyond IMPORT_LIMITS: `textChars` mirrors the store's 20 MiB evidence cap so a parser never trusts its caller to have enforced it. */
const ASSURANCE_LIMITS = { textChars: 20 * 1024 * 1024, schedule: 10_000, traceNodes: 10_000, traceDepth: 32, example: 2000, warnings: 50 } as const;

type Json = Record<string, unknown>;

const isObject = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);
const get = (v: unknown, ...keys: string[]): unknown => keys.reduce<unknown>((o, k) => (isObject(o) && Object.hasOwn(o, k) ? o[k] : undefined), v);

/** Control and invisible formatting characters become spaces, whitespace collapses, the text is clipped, and secret-looking text is replaced, never stored. */
const clip = (v: unknown, max: number): string | null => {
  if (typeof v !== "string" || v === "") {
    return null;
  }
  const text = v.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, " ").replace(/\s+/g, " ").trim();
  const clipped = text.length > max ? text.slice(0, max) : text;
  return clipped === "" ? null : scanForSecrets(clipped) !== null ? "[redacted: the text looked like a secret]" : clipped;
};
const cleanMessage = (v: unknown): string | null => clip(v, IMPORT_LIMITS.message);
/** The repository root of the parse in progress (parsing is synchronous). */
let assuranceRoot: string | null = null;
/** Only repository-relative paths are kept: absolute, drive-letter, `..`, control-character and secret-looking paths become null. */
const safeFile = (v: unknown): string | null => {
  if (typeof v !== "string" || v === "") {
    return null;
  }
  let f = v.replace(/\\/g, "/").replace(/^(?:\.\/)+/, "");
  if (assuranceRoot !== null && f.startsWith(`${assuranceRoot}/`)) {
    f = f.slice(assuranceRoot.length + 1); // a tool's absolute path under the repository becomes repository-relative
  }
  const unsafe = f === "" || f.startsWith("/") || /^[A-Za-z]:/.test(f) || f.split("/").includes("..") || f.length > 1024 || /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(f);
  return unsafe || scanForSecrets(f) !== null ? null : f;
};
const positiveInt = (v: unknown): number | null => (Number.isSafeInteger(v) && (v as number) > 0 ? (v as number) : null);
const countOf = (v: unknown): number | null => (Number.isSafeInteger(v) && (v as number) >= 0 ? (v as number) : null);
const seedOf = (v: unknown): string | null => (typeof v === "number" && Number.isFinite(v) ? String(v) : clip(v, 100));

/** Warnings are de-duplicated and capped so a hostile artifact cannot grow them without bound. */
function warn(out: NormalizedEvidence, message: string, partial = true): void {
  out.partial = out.partial || partial;
  if (!out.warnings.includes(message) && out.warnings.length < ASSURANCE_LIMITS.warnings) {
    out.warnings.push(message);
  }
}

function newOut(format: AssuranceFormat, assurance: AssuranceDetail): NormalizedEvidence {
  return { format, results: [], coverage: [], findings: [], partial: false, warnings: [], assurance };
}

function parseRoot(text: string): Json {
  if (text.length > ASSURANCE_LIMITS.textChars) {
    throw new EngbrainError("POLICY_REFUSED", `the artifact is larger than ${ASSURANCE_LIMITS.textChars} characters`);
  }
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    throw new EngbrainError("POLICY_REFUSED", "not valid JSON");
  }
  if (!isObject(doc)) {
    throw new EngbrainError("POLICY_REFUSED", "the artifact must be a JSON object");
  }
  return doc;
}

function requireBoolean(doc: Json, key: string, what: string): boolean {
  const v = doc[key];
  if (typeof v !== "boolean") {
    throw new EngbrainError("POLICY_REFUSED", `not a ${what} artifact (\`${key}\` must be true or false)`);
  }
  return v;
}

/** A bounded, cleaned copy of arbitrary JSON (a trace or a counterexample): strings are cleaned, depth and node count are capped, keys are own data properties only. */
function sanitizeJson(value: unknown, out: NormalizedEvidence): unknown {
  const budget = { nodes: 0, truncated: false };
  const visit = (v: unknown, depth: number): unknown => {
    budget.nodes += 1;
    if (budget.nodes > ASSURANCE_LIMITS.traceNodes || depth > ASSURANCE_LIMITS.traceDepth) {
      budget.truncated = true;
      return null;
    }
    if (typeof v === "string") {
      return clip(v, ASSURANCE_LIMITS.example);
    }
    if (typeof v === "number" || typeof v === "boolean" || v === null) {
      return v;
    }
    const entries: Array<[string, unknown]> = Array.isArray(v) ? v.map((x, i) => [String(i), x]) : isObject(v) ? Object.entries(v) : [];
    if (entries.length > ASSURANCE_LIMITS.traceNodes) {
      budget.truncated = true;
    }
    const kept = entries.slice(0, ASSURANCE_LIMITS.traceNodes).map(([k, x]): [string, unknown] => [clip(k, IMPORT_LIMITS.name) ?? "_", visit(x, depth + 1)]);
    return Array.isArray(v) ? kept.map(([, x]) => x) : Object.fromEntries(kept); // fromEntries defines own properties: a "__proto__" key cannot reach a prototype
  };
  const result = visit(value, 0);
  if (budget.truncated) {
    warn(out, "a trace or counterexample was larger or deeper than the limit and was truncated");
  }
  return result;
}

/** A counterexample is stored as text: a string as-is, anything else as bounded JSON. */
function exampleText(value: unknown, out: NormalizedEvidence): string | null {
  if (value === undefined || value === null) {
    return null;
  }
  return typeof value === "string" ? clip(value, ASSURANCE_LIMITS.example) : clip(JSON.stringify(sanitizeJson(value, out)), ASSURANCE_LIMITS.example);
}

export function parseAssurance(format: EvidenceFormat, text: string, repoRoot: string | null = null): NormalizedEvidence {
  assuranceRoot = repoRoot === null ? null : repoRoot.replace(/\\/g, "/").replace(/\/+$/, "");
  try {
    return parseAssuranceFormat(format, text);
  } finally {
    assuranceRoot = null;
  }
}

function parseAssuranceFormat(format: EvidenceFormat, text: string): NormalizedEvidence {
  switch (format) {
    case "stryker": return parseStryker(parseRoot(text));
    case "fastcheck": return parseFastCheck(parseRoot(text));
    case "hypothesis": return parseHypothesis(parseRoot(text));
    case "semgrep_json": return parseSemgrep(parseRoot(text));
    case "tla": case "z3": return parseFormal(format, parseRoot(text));
    case "race_log": return parseRaceLog(parseRoot(text));
    default: throw new EngbrainError("POLICY_REFUSED", `${String(format)} is not an assurance format`);
  }
}

// ---------- mutation (Stryker) ----------

const STRYKER_STATUS: Readonly<Record<string, MutantRecord["status"]>> = {
  Killed: "killed", Survived: "survived", NoCoverage: "survived",
  Timeout: "inconclusive", RuntimeError: "inconclusive", CompileError: "inconclusive", Ignored: "inconclusive", Pending: "inconclusive"
};
const MUTANT_OUTCOME: Readonly<Record<MutantRecord["status"], Outcome>> = { killed: "passed", survived: "failed", equivalent: "skipped", inconclusive: "skipped" };

/** One result per mutant (killed passed, survived failed, the rest skipped) so counts are meaningful; the mutants themselves go to `assurance.mutants`. */
function parseStryker(doc: Json): NormalizedEvidence {
  const files = doc["files"];
  if (!isObject(files)) {
    throw new EngbrainError("POLICY_REFUSED", "not a Stryker mutation report (no files object)");
  }
  const mutants: MutantRecord[] = [];
  const out = newOut("stryker", { kind: "mutation", tool: "stryker", toolVersion: clip(get(doc, "framework", "version"), 80), mutants });
  for (const [rawPath, entry] of Object.entries(files)) {
    if (mutants.length >= IMPORT_LIMITS.results) {
      warn(out, "mutant limit reached: the rest of the artifact was not read");
      break;
    }
    const file = safeFile(rawPath);
    const list = get(entry, "mutants");
    if (file === null || !Array.isArray(list)) {
      warn(out, "a file entry named an unsafe or absolute path, or had no mutants array, and was skipped");
      continue;
    }
    readMutants(out, mutants, file, list);
  }
  if (mutants.length === 0) {
    warn(out, "no mutants were found");
  }
  return out;
}

function readMutants(out: NormalizedEvidence, mutants: MutantRecord[], file: string, list: unknown[]): void {
  for (const [index, m] of list.entries()) {
    if (mutants.length >= IMPORT_LIMITS.results) {
      warn(out, "mutant limit reached: the rest of the artifact was not read");
      return;
    }
    if (!isObject(m)) {
      warn(out, "a mutant entry was not an object and was skipped");
      continue;
    }
    const rawStatus = typeof m["status"] === "string" ? m["status"] : "";
    const known = Object.hasOwn(STRYKER_STATUS, rawStatus);
    if (!known) {
      warn(out, "a mutant had an unknown status and was recorded as inconclusive", false);
    }
    const status = known ? (STRYKER_STATUS[rawStatus] ?? "inconclusive") : "inconclusive";
    const id = typeof m["id"] === "number" ? String(m["id"]) : (clip(m["id"], 100) ?? String(index));
    const line = positiveInt(get(m, "location", "start", "line"));
    const mutator = clip(m["mutatorName"], 120);
    mutants.push({ key: `${file}#${id}`, file, line, mutator, status });
    out.results.push(mutantResult(file, id, line, mutator, status, clip(rawStatus, 40)));
  }
}

function mutantResult(file: string, id: string, line: number | null, mutator: string | null, status: MutantRecord["status"], rawStatus: string | null): NormalizedResult {
  const where = line === null ? "" : ` at line ${line}`;
  return {
    suite: clip(file, IMPORT_LIMITS.name), name: clip(`${mutator ?? "mutant"} #${id}${where}`, IMPORT_LIMITS.name) ?? "(unnamed)", file,
    outcome: MUTANT_OUTCOME[status], durationMs: null, message: cleanMessage(`mutant ${status} (stryker status ${rawStatus ?? "missing"})`)
  };
}

// ---------- property-based (fast-check, Hypothesis) ----------

/** fast-check's counterexamplePath is "runIndex:shrinkStep:...": every segment after the first is one shrink. */
const shrinkStepsFromPath = (v: unknown): number | null => (typeof v === "string" && v.length <= 100_000 && /^\d+(?::\d+)*$/.test(v) ? v.split(":").length - 1 : null);

function propertyOut(format: "fastcheck" | "hypothesis", doc: Json, detail: NonNullable<AssuranceDetail["property"]>, name: string | null, defaultTool: string): NormalizedEvidence {
  const out = newOut(format, { kind: "property", tool: clip(doc["tool"], 80) ?? defaultTool, toolVersion: clip(doc["version"], 80), property: detail });
  const example = detail.shrunk ?? detail.counterexample;
  out.results.push({
    suite: null, name: name ?? "(unnamed property)", file: null, outcome: detail.failed ? "failed" : "passed", durationMs: null,
    message: cleanMessage(detail.failed ? `falsified (seed ${detail.seed ?? "unknown"})${example === null ? "" : `: ${example}`}` : `held for ${detail.numRuns ?? "an unknown number of"} runs (seed ${detail.seed ?? "unknown"})`)
  });
  return out;
}

function checkProperty(out: NormalizedEvidence, detail: NonNullable<AssuranceDetail["property"]>): void {
  if (detail.seed === null) {
    warn(out, "the artifact has no seed: the run cannot be replayed");
  }
  if (detail.failed && detail.counterexample === null) {
    warn(out, "the property failed but no counterexample was recorded");
  }
}

function parseFastCheck(doc: Json): NormalizedEvidence {
  const failed = requireBoolean(doc, "failed", "fast-check");
  const scratch = newOut("fastcheck", { kind: "property", tool: null, toolVersion: null }); // collects truncation warnings from the examples
  const detail = {
    seed: seedOf(doc["seed"]), numRuns: countOf(doc["numRuns"]), failed,
    counterexample: exampleText(doc["counterexample"], scratch), shrunk: exampleText(doc["shrunk"], scratch),
    shrinkSteps: countOf(doc["shrinkSteps"]) ?? shrinkStepsFromPath(doc["shrinkPath"])
  };
  const out = propertyOut("fastcheck", doc, detail, clip(doc["property"] ?? doc["test"], IMPORT_LIMITS.name), "fast-check");
  scratch.warnings.forEach((w) => warn(out, w));
  checkProperty(out, detail);
  if (detail.numRuns === null) {
    warn(out, "the artifact does not say how many runs were made");
  }
  return out;
}

/** Hypothesis reports only the minimal (already shrunk) falsifying example, so it is stored as both the counterexample and the shrunk value. */
function parseHypothesis(doc: Json): NormalizedEvidence {
  const failed = requireBoolean(doc, "failed", "Hypothesis");
  const scratch = newOut("hypothesis", { kind: "property", tool: null, toolVersion: null });
  const example = exampleText(doc["falsifying_example"], scratch);
  const detail = { seed: seedOf(doc["seed"]), numRuns: null, failed, counterexample: example, shrunk: example, shrinkSteps: countOf(doc["shrink_steps"]) };
  const test = clip(doc["test"], IMPORT_LIMITS.name);
  const out = propertyOut("hypothesis", doc, detail, test, "hypothesis");
  scratch.warnings.forEach((w) => warn(out, w));
  checkProperty(out, detail);
  if (test === null) {
    warn(out, "the artifact does not name the test");
  }
  return out;
}

// ---------- SAST (Semgrep) ----------

const SEMGREP_LEVEL: Readonly<Record<string, string>> = { ERROR: "error", WARNING: "warning", INFO: "note" };

function parseSemgrep(doc: Json): NormalizedEvidence {
  const results = doc["results"];
  if (!Array.isArray(results)) {
    throw new EngbrainError("POLICY_REFUSED", "not a Semgrep JSON report (no results array)");
  }
  const out = newOut("semgrep_json", { kind: "sast", tool: "semgrep", toolVersion: clip(doc["version"], 80) });
  for (const r of results) {
    if (out.findings.length >= IMPORT_LIMITS.findings) {
      warn(out, "finding limit reached: the rest of the artifact was not read");
      break;
    }
    if (!isObject(r)) {
      warn(out, "a result entry was not an object and was skipped");
      continue;
    }
    out.findings.push(semgrepFinding(out, r));
  }
  const errors = doc["errors"];
  if (Array.isArray(errors) && errors.length > 0) {
    warn(out, `the scan reported ${errors.length} errors: some files or rules may not have been scanned`);
  }
  return out;
}

function semgrepFinding(out: NormalizedEvidence, r: Json): NormalizedEvidence["findings"][number] {
  const file = safeFile(r["path"]);
  if (file === null && r["path"] !== undefined) {
    warn(out, "a finding named an unsafe or absolute path: its file was not stored", false);
  }
  const severity = get(r, "extra", "severity");
  const known = typeof severity === "string" && Object.hasOwn(SEMGREP_LEVEL, severity);
  if (!known) {
    warn(out, "a finding had an unknown severity and was recorded as a warning", false);
  }
  return {
    tool: "semgrep", rule: clip(r["check_id"], 120), level: known ? (SEMGREP_LEVEL[severity] ?? "warning") : "warning",
    file, line: positiveInt(get(r, "start", "line")), message: cleanMessage(get(r, "extra", "message"))
  };
}

// ---------- formal (TLA+, Z3) ----------

type FormalResult = NonNullable<AssuranceDetail["formal"]>["result"];
const FORMAL_OUTCOME: Readonly<Record<FormalResult, Outcome>> = { counterexample: "failed", scoped_success: "passed", unknown: "skipped", error: "error" };
const FORMAL_MESSAGE: Readonly<Record<FormalResult, string>> = {
  counterexample: "counterexample found: the property is violated in the model",
  scoped_success: "scoped success: no violation within this model and its bounds only; this is not a proof about the application",
  unknown: "the tool returned unknown: no conclusion",
  error: "the tool reported an error: no conclusion"
};

/** z3 checks the negated invariant, so `unsat` is a scoped success and `sat` a counterexample. TLA+ results are not satisfiability answers, so sat/unsat is refused. */
function formalResult(format: "tla" | "z3", raw: unknown): FormalResult {
  if (raw === "counterexample" || raw === "scoped_success" || raw === "unknown" || raw === "error") {
    return raw;
  }
  if (format === "z3" && (raw === "sat" || raw === "unsat")) {
    return raw === "sat" ? "counterexample" : "scoped_success";
  }
  throw new EngbrainError("POLICY_REFUSED", `not a ${format} result artifact (result must be ${format === "z3" ? "sat, unsat, " : ""}counterexample, scoped_success, unknown or error)`);
}

function parseFormal(format: "tla" | "z3", doc: Json): NormalizedEvidence {
  const result = formalResult(format, doc["result"]);
  const rawSha = doc["modelSha256"];
  const modelSha256 = typeof rawSha === "string" && /^[0-9a-f]{64}$/i.test(rawSha) ? rawSha.toLowerCase() : null;
  const specVersion = clip(typeof doc["specVersion"] === "number" ? String(doc["specVersion"]) : doc["specVersion"], 80);
  const formal = { result, modelSha256, specVersion, counterexample: null as unknown };
  const out = newOut(format, { kind: "formal", tool: clip(doc["tool"], 80), toolVersion: clip(doc["version"], 80), formal });
  const hasTrace = doc["trace"] !== undefined && doc["trace"] !== null;
  if (result === "counterexample") {
    formal.counterexample = hasTrace ? sanitizeJson(doc["trace"], out) : null;
    if (!hasTrace) {
      warn(out, "a counterexample was reported without a trace: it cannot be replayed");
    }
  } else if (hasTrace) {
    warn(out, `a trace was supplied with a ${result} result and was ignored`, false);
  }
  checkFormalProvenance(out, doc, modelSha256, specVersion);
  out.results.push({ suite: null, name: clip(`${format} model check${specVersion === null ? "" : ` (spec ${specVersion})`}`, IMPORT_LIMITS.name) ?? format, file: null, outcome: FORMAL_OUTCOME[result], durationMs: null, message: FORMAL_MESSAGE[result] });
  return out;
}

function checkFormalProvenance(out: NormalizedEvidence, doc: Json, modelSha256: string | null, specVersion: string | null): void {
  if (out.assurance?.tool === null || out.assurance?.toolVersion === null) {
    warn(out, "the artifact does not name the tool and its version");
  }
  if (modelSha256 === null) {
    warn(out, doc["modelSha256"] === undefined ? "the artifact has no modelSha256: the result cannot be tied to a model" : "modelSha256 is not a 64-character hex digest");
  }
  if (specVersion === null) {
    warn(out, "the artifact has no specVersion");
  }
}

// ---------- race schedules ----------

function parseRaceLog(doc: Json): NormalizedEvidence {
  const schedule = doc["schedule"];
  const violation = doc["violation"];
  if (!Array.isArray(schedule) || !schedule.every((s) => typeof s === "string")) {
    throw new EngbrainError("POLICY_REFUSED", "not a race log (schedule must be an array of strings)");
  }
  if (violation !== null && typeof violation !== "string") {
    throw new EngbrainError("POLICY_REFUSED", "not a race log (violation must be a string or null)");
  }
  const race = {
    seed: seedOf(doc["seed"]),
    schedule: (schedule as string[]).slice(0, ASSURANCE_LIMITS.schedule).map((s) => clip(s, IMPORT_LIMITS.name) ?? "(empty step)"),
    violation: violation === null ? null : (cleanMessage(violation) ?? "(unspecified violation)")
  };
  const out = newOut("race_log", { kind: "race", tool: clip(doc["tool"], 80), toolVersion: clip(doc["version"], 80), race });
  if (schedule.length > ASSURANCE_LIMITS.schedule) {
    warn(out, `the schedule has ${schedule.length} steps: only the first ${ASSURANCE_LIMITS.schedule} were kept`);
  }
  if (race.seed === null) {
    warn(out, "the artifact has no seed: the schedule cannot be replayed");
  }
  if (out.assurance?.tool === null) {
    warn(out, "the artifact does not name the tool");
  }
  out.results.push({
    suite: null, name: `race schedule (seed ${race.seed ?? "unknown"})`, file: null, outcome: race.violation === null ? "passed" : "failed", durationMs: null,
    message: race.violation ?? cleanMessage(`no violation in ${schedule.length} scheduled steps`)
  });
  return out;
}
