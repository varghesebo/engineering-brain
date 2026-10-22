import { createHash } from "node:crypto";
import type Database from "better-sqlite3";
import { findTestsFor, TEST_PATH } from "../testDiscovery.js";
import { currentGenerationId } from "../store/generations.js";
import { analyzeImpact, type ImpactAnalysis, type ImpactOptions } from "./impactEngine.js";

/**
 * Advisory test selection. A test is selected with a stated PROOF CLASS (it imports a changed file, imports an impacted file through a chain, or merely shares a name), and every changed or
 * impacted file that no test maps to is reported as an UNMAPPED area: a missing mapping is never read as "safe". A deterministic sample of the tests that were not selected is offered as a hedge
 * against edges the index cannot see, and `selectionRecall` compares a selection with a baseline run so the miss rate is measured instead of assumed.
 */
export const SELECTION_LIMITS = { maxTargets: 300, perTarget: 20, maxSelected: 500, maxSample: 100 } as const;

export type SelectionProof = "changed_test" | "imports_changed_file" | "imports_through_chain" | "name_match" | "imports_impacted_file";
export interface SelectedTest { path: string; proof: SelectionProof; for: string[]; certainty: "resolved" | "heuristic" }
export interface TestSelection {
  generationId: number | null;
  analysis: Pick<ImpactAnalysis, "inputs" | "unknownInputs" | "boundary" | "missedEdgeRisk" | "truncated" | "basis">;
  selected: SelectedTest[];
  /** Changed or impacted source files with no mapped test: UNKNOWN coverage, not safety. */
  unmapped: string[];
  sample: Array<{ path: string; reason: string }>;
  totalTests: number;
  /** True when a cap cut the analysis short: the omitted files/tests are listed in `unmapped` as unknown, never silently dropped. */
  truncated: boolean;
  advisory: string;
}

const ADVISORY = "Advisory only. This selection can miss tests: it sees static imports and file names, not dynamic wiring, fixtures, configuration or shared state. A file with no mapped test is UNKNOWN, not safe. Run the full suite before relying on a change.";
const PROOF_ORDER: Record<SelectionProof, number> = { changed_test: 0, imports_changed_file: 1, imports_through_chain: 2, imports_impacted_file: 3, name_match: 4 };

const rank = (seed: string, path: string): string => createHash("sha256").update(`${seed}\0${path}`).digest("hex");

export function selectTests(db: Database.Database, options: ImpactOptions & { sample?: number; sampleSeed?: string }): TestSelection {
  return db.transaction((): TestSelection => {
    const analysis = analyzeImpact(db, options);
    const generationId = currentGenerationId(db);
    const picked = new Map<string, SelectedTest>();
    const unmapped: string[] = [];
    let truncated = analysis.truncated;
    const add = (test: SelectedTest): void => {
      const existing = picked.get(test.path);
      if (existing === undefined || PROOF_ORDER[test.proof] < PROOF_ORDER[existing.proof]) {
        picked.set(test.path, { ...test, for: [...new Set([...(existing?.for ?? []), ...test.for])].slice(0, 5) });
      } else {
        existing.for = [...new Set([...existing.for, ...test.for])].slice(0, 5);
      }
    };
    if (generationId !== null) {
      const targets: Array<{ path: string; direct: boolean; impactClass?: string }> = [
        ...analysis.inputs.filter((p) => !analysis.unknownInputs.some((u) => u.path === p)).map((path) => ({ path, direct: true })),
        ...analysis.impacted.filter((i) => i.class !== "inferred_potential").map((i) => ({ path: i.path, direct: false, impactClass: i.class }))
      ];
      if (targets.length > SELECTION_LIMITS.maxTargets) {
        truncated = true;
        unmapped.push(...targets.slice(SELECTION_LIMITS.maxTargets).filter((t) => !TEST_PATH.test(t.path)).map((t) => t.path)); // analysed by nobody: unknown, not safe
        targets.length = SELECTION_LIMITS.maxTargets;
      }
      for (const target of targets) {
        if (TEST_PATH.test(target.path)) {
          add({ path: target.path, proof: target.direct ? "changed_test" : target.impactClass === "direct_proven" ? "imports_changed_file" : "imports_through_chain", for: [target.path], certainty: "resolved" });
          continue;
        }
        const tests = findTestsFor(db, generationId, target.path, SELECTION_LIMITS.perTarget);
        if (tests.length === 0) {
          unmapped.push(target.path);
        }
        for (const t of tests) {
          const proof: SelectionProof = t.basis === "name_match" ? "name_match" : !target.direct ? "imports_impacted_file" : t.basis === "imports_target" ? "imports_changed_file" : "imports_through_chain";
          add({ path: t.path, proof, for: [target.path], certainty: t.certainty });
        }
      }
    }
    const ordered = [...picked.values()].sort((a, b) => PROOF_ORDER[a.proof] - PROOF_ORDER[b.proof] || (a.path < b.path ? -1 : 1));
    truncated = truncated || ordered.length > SELECTION_LIMITS.maxSelected;
    const selected = ordered.slice(0, SELECTION_LIMITS.maxSelected);
    const all = generationId === null ? [] : (db.prepare("SELECT path FROM generation_files WHERE generation_id = ? AND content_hash IS NOT NULL").all(generationId) as Array<{ path: string }>).map((r) => r.path).filter((p) => TEST_PATH.test(p));
    const chosen = new Set(selected.map((s) => s.path));
    const wanted = Math.min(Math.max(0, Math.floor(options.sample ?? 0)), SELECTION_LIMITS.maxSample);
    const seed = options.sampleSeed ?? analysis.basis.since ?? analysis.inputs.join(",");
    const sample = all.filter((p) => !chosen.has(p)).map((path) => ({ path, key: rank(seed, path) })).sort((a, b) => (a.key < b.key ? -1 : 1)).slice(0, wanted).map((x) => x.path).map((path) => ({ path, reason: "deterministic sample of unselected tests (hedge against edges the index cannot see)" }));
    return {
      generationId,
      analysis: { inputs: analysis.inputs, unknownInputs: analysis.unknownInputs, boundary: analysis.boundary, missedEdgeRisk: analysis.missedEdgeRisk, truncated: analysis.truncated, basis: analysis.basis },
      selected, unmapped: [...new Set(unmapped)].sort(), sample, totalTests: all.length, truncated, advisory: ADVISORY
    };
  })();
}

/** Recall of a selection against a baseline: the tests that FAILED in a full run (or any known-relevant set) and whether the selection (plus sample) contained each. */
export function selectionRecall(selection: Pick<TestSelection, "selected" | "sample">, baselineRelevant: string[]): { recall: number | null; missed: string[]; found: string[] } {
  const have = new Set([...selection.selected.map((s) => s.path), ...selection.sample.map((s) => s.path)]);
  const relevant = [...new Set(baselineRelevant)];
  const found = relevant.filter((p) => have.has(p));
  return { recall: relevant.length === 0 ? null : found.length / relevant.length, missed: relevant.filter((p) => !have.has(p)).sort(), found: found.sort() };
}
