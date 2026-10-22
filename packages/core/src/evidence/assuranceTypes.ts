/** Structured detail of an adversarial-assurance artifact (mutation, property, SAST, formal, race), produced by the parsers and stored with the import. */
export interface MutantRecord { key: string; file: string; line: number | null; mutator: string | null; status: "killed" | "survived" | "equivalent" | "inconclusive" }
export interface AssuranceDetail {
  kind: "mutation" | "property" | "sast" | "formal" | "race";
  tool: string | null;
  toolVersion: string | null;
  mutants?: MutantRecord[];
  property?: { seed: string | null; numRuns: number | null; failed: boolean; counterexample: string | null; shrunk: string | null; shrinkSteps: number | null };
  formal?: { result: "counterexample" | "scoped_success" | "unknown" | "error"; modelSha256: string | null; specVersion: string | null; counterexample: unknown };
  race?: { seed: string | null; schedule: string[]; violation: string | null };
}
