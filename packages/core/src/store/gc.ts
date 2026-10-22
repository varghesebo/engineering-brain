import type Database from "better-sqlite3";

export interface GcResult {
  generationsRemoved: number;
  factsRemoved: number;
}

/**
 * Retention + mark-and-sweep. Keeps the newest `keep` complete generations (always including the current one),
 * removes abandoned ones, then deletes facts no retained manifest references. Caller must hold the writer lock.
 * Facts still referenced by the commit ledger (commit_changes) are kept: history evidence is never deleted by retention. Evidence (a later stage) will keep its own fingerprint strings, so it survives a generation being removed.
 */
export function collectGarbage(db: Database.Database, keep: number): GcResult {
  return db.transaction((): GcResult => {
    const current = (db.prepare("SELECT current_generation_id AS id FROM store_meta WHERE singleton = 1").get() as { id: number | null }).id;
    const complete = db.prepare("SELECT id FROM generations WHERE status = 'complete' ORDER BY id DESC").all() as Array<{ id: number }>;
    const retained = new Set(complete.slice(0, keep).map((row) => row.id));
    if (current !== null) {
      retained.add(current);
    }
    const remove = db.prepare("DELETE FROM generations WHERE id = ?");
    let generationsRemoved = 0;
    for (const row of complete) {
      if (!retained.has(row.id)) {
        generationsRemoved += remove.run(row.id).changes;
      }
    }
    generationsRemoved += db.prepare("DELETE FROM generations WHERE status = 'abandoned'").run().changes;

    const factsRemoved = db
      .prepare(
        `DELETE FROM file_facts WHERE NOT EXISTS (
           SELECT 1 FROM generation_files gf
           JOIN generation_extractors ge ON ge.generation_id = gf.generation_id
           WHERE gf.content_hash = file_facts.content_hash
             AND ge.extractor_id = file_facts.extractor_id AND ge.extractor_version = file_facts.extractor_version
         ) AND NOT EXISTS (
           SELECT 1 FROM commit_changes cc WHERE cc.new_content_hash = file_facts.content_hash OR cc.old_content_hash = file_facts.content_hash
         )`
      )
      .run().changes;
    return { generationsRemoved, factsRemoved };
  }).immediate();
}
