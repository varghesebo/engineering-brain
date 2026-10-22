import { createHash } from "node:crypto";
import type Database from "better-sqlite3";
import { EngbrainError } from "../errors.js";

/**
 * The source-tree fingerprint a task is bound to: the published generation's source fingerprint plus the history checkpoint (commit and dirty overlay) it was built at. It is computed from the
 * store by trusted code, never typed by an agent. It describes the last PUBLISHED index, so callers must refuse to use it when the index is stale.
 */
export function repositoryFingerprint(db: Database.Database): string {
  const gen = db.prepare("SELECT g.source_fingerprint AS fp, g.revision AS rev FROM store_meta m JOIN generations g ON g.id = m.current_generation_id").get() as { fp: string | null; rev: string | null } | undefined;
  if (gen === undefined || gen.fp === null) {
    throw new EngbrainError("NOT_INITIALIZED", "no published index yet: run `engbrain index`");
  }
  const checkpoint = db.prepare("SELECT processed_oid AS oid, overlay_hash AS overlay FROM history_checkpoints WHERE ref_key = 'HEAD'").get() as { oid: string | null; overlay: string | null } | undefined;
  return createHash("sha256").update(JSON.stringify(["engbrain-source-v1", gen.fp, gen.rev, checkpoint?.oid ?? null, checkpoint?.overlay ?? null])).digest("hex");
}
