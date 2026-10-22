import { refreshRepository, type RefreshOptions } from "@engbrain/core";
import { openFor } from "./env.js";

export type Opened = Awaited<ReturnType<typeof openFor>>;

export async function withStore<T>(repo: string, home: string, fn: (o: Opened) => Promise<T> | T, init = false): Promise<T> {
  const o = await openFor(repo, home, init);
  try {
    return await fn(o);
  } finally {
    o.close();
  }
}

export const refresh = (repo: string, home: string, extra: Partial<RefreshOptions> = {}, init = false) =>
  withStore(repo, home, (o) => refreshRepository({ store: o.store, git: o.info, hardenedGit: o.git, ...extra }), init);

/** The ledger as comparable data: everything that identifies WHAT was recorded, nothing about when, how, or in which run. */
export function ledgerProjection(o: Opened): unknown {
  const db = o.store.db;
  return {
    commits: db.prepare("SELECT commit_oid, tree_oid, availability, subject, changes_truncated FROM git_commits WHERE ingest_complete = 1 ORDER BY commit_oid").all(),
    parents: db.prepare("SELECT commit_oid, ordinal, parent_oid FROM commit_parents ORDER BY commit_oid, ordinal").all(),
    changes: db.prepare("SELECT commit_oid, parent_ordinal, path, old_path, change_kind, old_blob, new_blob, old_content_hash, new_content_hash, rename_score, excluded_reason FROM commit_changes ORDER BY commit_oid, parent_ordinal, path").all(),
    deltas: db.prepare("SELECT * FROM commit_symbol_deltas ORDER BY commit_oid, parent_ordinal, path, delta, kind, qualified_name, ordinal").all(),
    blobs: db.prepare("SELECT blob_oid, content_hash, excluded_reason FROM blob_hashes ORDER BY blob_oid").all()
  };
}

export const checkpointOf = (o: Opened): unknown => o.store.db.prepare("SELECT processed_oid, generation_id, history_partial FROM history_checkpoints").get();
export const currentGeneration = (o: Opened): number | null => (o.store.db.prepare("SELECT current_generation_id AS g FROM store_meta").get() as { g: number | null }).g;
