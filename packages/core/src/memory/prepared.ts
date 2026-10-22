import type Database from "better-sqlite3";

const cache = new WeakMap<Database.Database, Map<string, Database.Statement>>();

/** A prepared statement cached per database handle: read paths issue thousands of identical lookups and must not re-prepare (and accumulate) statements. */
export function prep(db: Database.Database, sql: string): Database.Statement {
  let statements = cache.get(db);
  if (statements === undefined) {
    statements = new Map();
    cache.set(db, statements);
  }
  let statement = statements.get(sql);
  if (statement === undefined) {
    statement = db.prepare(sql);
    statements.set(sql, statement);
  }
  return statement;
}
