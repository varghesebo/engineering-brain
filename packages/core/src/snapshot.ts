import type Database from "better-sqlite3";
import { currentGenerationId } from "./store/generations.js";

/** Which published generation a read came from. Every response carries this so a reader can tell what it is looking at. */
export interface GenerationSnapshot {
  generationId: number;
  revision: string | null;
  /** Hash over the indexed (path, content hash) set: identifies the exact source state, including uncommitted edits. */
  sourceFingerprint: string | null;
  completedAt: string | null;
  hashVerifiedAt: string | null;
}

export function readSnapshot(db: Database.Database): GenerationSnapshot | null {
  const generationId = currentGenerationId(db);
  if (generationId === null) {
    return null;
  }
  const row = db.prepare("SELECT revision, source_fingerprint AS fp, completed_at AS completedAt, hash_verified_at AS verifiedAt FROM generations WHERE id = ?").get(generationId) as
    { revision: string | null; fp: string | null; completedAt: string | null; verifiedAt: string | null } | undefined;
  return row === undefined ? null : { generationId, revision: row.revision, sourceFingerprint: row.fp, completedAt: row.completedAt, hashVerifiedAt: row.verifiedAt };
}

/** How a fact or edge was established, in the dimensions the design keeps separate (docs/ontology-and-schema.md). */
export interface Provenance {
  extractionMethod: "tree_sitter_syntax" | "manifest" | "graph_resolution";
  semanticCertainty: "syntactic_only" | "resolved" | "ambiguous" | "unresolved" | "heuristic";
  evidenceType: "static_analysis";
  extractor: string | null;
  extractorVersion?: string | null;
  contentHash: string | null;
}

export const SYNTAX_PROVENANCE = (extractor: string, contentHash: string, extractorVersion: string | null = null): Provenance => ({
  extractionMethod: "tree_sitter_syntax", semanticCertainty: "syntactic_only", evidenceType: "static_analysis", extractor, extractorVersion, contentHash
});
