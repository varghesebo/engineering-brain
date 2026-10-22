import type Database from "better-sqlite3";
import { EngbrainError } from "../errors.js";
import { impact, resolveNode, type Budget, type NodeRef } from "../graph.js";
import { currentGenerationId } from "../store/generations.js";
import { changesSince } from "../history/changes.js";

/**
 * Impact of a set of changed files, classified by how strong the evidence is:
 *  - `direct_proven`: a RESOLVED static import/re-export/reference edge from the dependent to a changed file (one hop);
 *  - `transitive`: reached through a chain of resolved module edges (distance >= 2);
 *  - `inferred_potential`: an unresolved/ambiguous import whose specifier resembles a changed file's name (a heuristic hint, not an edge);
 *  - `unknown`: input the index cannot speak about (not indexed, deleted) plus the repository-wide boundary of dynamic/unresolved imports that may hide dependents.
 * It never says that anything breaks or that something is safe: absence from the lists is only absence of a recorded static edge.
 */
export const IMPACT_LIMITS = { maxInputs: 200, perInputNodes: 500 } as const;

export type ImpactClass = "direct_proven" | "transitive" | "inferred_potential";
export interface ImpactedItem { path: string; class: ImpactClass; distance: number; via: string; because: string[] }
export interface ImpactAnalysis {
  generationId: number | null;
  inputs: string[];
  /** Inputs the index cannot analyse, each with the reason. A path here is an UNKNOWN area, never a safe one. */
  unknownInputs: Array<{ path: string; reason: string }>;
  impacted: ImpactedItem[];
  boundary: { dynamicImports: number; unresolvedImports: number; ambiguousImports: number; unresolvedBindings: number };
  missedEdgeRisk: { level: "low" | "medium" | "high"; reasons: string[] };
  truncated: boolean;
  basis: { since: string | null; relation: string | null; historyPartial: boolean | null };
  disclaimer: string;
}

const DISCLAIMER =
  "Potential structural effects from recorded static edges only. Not proof of breakage and not proof of safety: dynamic or unresolved imports, string-based wiring, configuration and runtime behaviour are invisible to it. Absence from the lists is not evidence of independence.";
const RANK: Record<ImpactClass, number> = { direct_proven: 0, transitive: 1, inferred_potential: 2 };

export interface ImpactOptions { files?: string[]; since?: string; budget?: Partial<Budget> }

/** Paths changed since a base, from the ledger (never from git). Returns only paths, de-duplicated, with the relation so a caller can state when the base was unknown. */
export function changedPathsSince(db: Database.Database, since: string): { paths: string[]; relation: string; historyPartial: boolean; truncated: boolean } {
  const result = changesSince(db, { since });
  const paths = new Set<string>();
  for (const commit of result.commits) {
    for (const group of commit.changesByParent) {
      for (const change of group.changes) {
        paths.add(change.path);
        if (change.oldPath !== null) {
          paths.add(change.oldPath);
        }
      }
    }
  }
  return { paths: [...paths].sort(), relation: result.relation, historyPartial: result.historyPartial, truncated: result.truncated };
}

export function analyzeImpact(db: Database.Database, options: ImpactOptions): ImpactAnalysis {
  return db.transaction((): ImpactAnalysis => {
    const generationId = currentGenerationId(db);
    let inputs = [...new Set(options.files ?? [])];
    let basis: ImpactAnalysis["basis"] = { since: null, relation: null, historyPartial: null };
    const unknownInputs: ImpactAnalysis["unknownInputs"] = [];
    let truncated = false;
    if (options.since !== undefined) {
      const since = changedPathsSince(db, options.since);
      basis = { since: options.since, relation: since.relation, historyPartial: since.historyPartial };
      truncated = since.truncated;
      if (since.relation !== "ancestor" && since.paths.length === 0) {
        unknownInputs.push({ path: "(everything since the base)", reason: `the base commit relation is "${since.relation}": the ledger cannot say what changed` });
      }
      inputs = [...new Set([...inputs, ...since.paths])];
    }
    if (inputs.length > IMPACT_LIMITS.maxInputs) {
      truncated = true;
      unknownInputs.push({ path: `(${inputs.length - IMPACT_LIMITS.maxInputs} more changed files)`, reason: `only the first ${IMPACT_LIMITS.maxInputs} inputs are analysed` });
      inputs = inputs.slice(0, IMPACT_LIMITS.maxInputs);
    }
    const base = { generationId, inputs, unknownInputs, basis, disclaimer: DISCLAIMER };
    const boundary = { dynamicImports: 0, unresolvedImports: 0, ambiguousImports: 0, unresolvedBindings: 0 };
    if (generationId === null) {
      return { ...base, impacted: [], boundary, missedEdgeRisk: { level: "high", reasons: ["no published index"] }, truncated };
    }
    const impacted = new Map<string, ImpactedItem>();
    const inputSet = new Set(inputs);
    const keep = (item: ImpactedItem): void => {
      if (inputSet.has(item.path)) {
        return; // a changed file is an input, not an effect
      }
      const existing = impacted.get(item.path);
      if (existing === undefined || RANK[item.class] < RANK[existing.class] || (item.class === existing.class && item.distance < existing.distance)) {
        impacted.set(item.path, { ...item, because: [...new Set([...(existing?.because ?? []), ...item.because])].slice(0, 5) });
      } else {
        existing.because = [...new Set([...existing.because, ...item.because])].slice(0, 5);
      }
    };
    let unclassifiable = 0;
    for (const path of inputs) {
      let node: NodeRef;
      try {
        node = resolveNode(db, { file: path });
      } catch (error) {
        if (error instanceof EngbrainError) {
          unknownInputs.push({ path, reason: "not in the published index (deleted, excluded, binary, or not a supported language): its dependents are unknown" });
          unclassifiable += 1;
          continue;
        }
        throw error;
      }
      const result = impact(db, node, { budget: { ...options.budget, maxNodes: Math.min(options.budget?.maxNodes ?? IMPACT_LIMITS.perInputNodes, IMPACT_LIMITS.perInputNodes) } });
      truncated = truncated || result.truncated.depth || result.truncated.nodes || result.truncated.edges || result.truncated.time;
      boundary.dynamicImports = result.unresolvedBoundary.dynamicImports;
      boundary.unresolvedImports = result.unresolvedBoundary.unresolvedImports;
      boundary.ambiguousImports = result.unresolvedBoundary.ambiguousImports;
      boundary.unresolvedBindings = result.unresolvedBoundary.unresolvedBindings;
      for (const a of result.affected) {
        if (a.node.path === null) {
          continue;
        }
        keep({ path: a.node.path, class: a.distance === 1 && a.via.resolution === "resolved" ? "direct_proven" : "transitive", distance: a.distance, via: `${a.via.kind}${a.via.resolution === "resolved" ? "" : ` (${a.via.resolution})`}`, because: [path] });
      }
      for (const edge of result.unresolvedBoundary.possiblyRelated) {
        if (edge.src.path !== null) {
          keep({ path: edge.src.path, class: "inferred_potential", distance: 0, via: `${edge.resolution} import of "${edge.dst.name}"`, because: [path] });
        }
      }
    }
    const reasons: string[] = [];
    let level: "low" | "medium" | "high" = "low";
    if (boundary.dynamicImports + boundary.unresolvedImports + boundary.ambiguousImports + boundary.unresolvedBindings > 0) {
      reasons.push(`the index records ${boundary.dynamicImports} dynamic, ${boundary.unresolvedImports} unresolved and ${boundary.ambiguousImports} ambiguous imports (and ${boundary.unresolvedBindings} unresolved bindings) that may hide dependents`);
      level = "medium";
    }
    if (unclassifiable > 0 || unknownInputs.length > 0) {
      reasons.push("some inputs are outside the index, so their dependents are unknown");
      level = "high";
    }
    if (truncated) {
      reasons.push("the analysis hit a budget or history limit");
      level = "high";
    }
    if (basis.historyPartial === true) {
      reasons.push("history is partial: older changes are not in the ledger");
      level = level === "low" ? "medium" : level;
    }
    return { ...base, impacted: [...impacted.values()].sort((a, b) => RANK[a.class] - RANK[b.class] || a.distance - b.distance || (a.path < b.path ? -1 : 1)), boundary, missedEdgeRisk: { level, reasons }, truncated };
  })();
}
