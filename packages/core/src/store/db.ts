import Database from "better-sqlite3";

export interface OpenOptions {
  readonly?: boolean;
  /** Create the file when missing. */
  create?: boolean;
}

/**
 * Opens a store database. The file may have come from an untrusted place (a cloned repo), so
 * `trusted_schema` is OFF: SQL objects stored in the file cannot call unsafe functions.
 * WAL needs a local filesystem (checked at init). synchronous=FULL favours durability of publication.
 */
export function openDatabase(path: string, options: OpenOptions = {}): Database.Database {
  const db = new Database(path, { readonly: options.readonly === true, fileMustExist: options.create !== true });
  db.pragma("trusted_schema = OFF");
  db.pragma("foreign_keys = ON");
  db.pragma("busy_timeout = 5000");
  if (options.readonly !== true) {
    db.pragma("journal_mode = WAL");
    db.pragma("synchronous = FULL");
  }
  return db;
}
