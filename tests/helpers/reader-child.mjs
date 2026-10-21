// Concurrent snapshot reader. Polls a store read-only for a fixed time, checking each snapshot is complete.
import Database from "better-sqlite3";

const [, , dbPath, durationMs] = process.argv;
const db = new Database(dbPath, { readonly: true, fileMustExist: true });
db.pragma("busy_timeout = 5000");
const generations = new Set();
let checks = 0;
let inconsistent = 0;
const end = Date.now() + Number(durationMs);
const pause = new Int32Array(new SharedArrayBuffer(4));
while (Date.now() < end) {
  db.transaction(() => {
    const meta = db.prepare("SELECT current_generation_id AS id FROM store_meta").get();
    if (meta?.id == null) {
      return;
    }
    const status = db.prepare("SELECT status FROM generations WHERE id = ?").get(meta.id);
    const rows = db.prepare("SELECT COUNT(*) AS n FROM generation_files WHERE generation_id = ?").get(meta.id).n;
    const missing = db
      .prepare(`SELECT COUNT(*) AS n FROM generation_files gf WHERE gf.generation_id = ? AND gf.content_hash IS NOT NULL
                AND NOT EXISTS (SELECT 1 FROM file_facts ff WHERE ff.content_hash = gf.content_hash)`)
      .get(meta.id).n;
    checks += 1;
    generations.add(meta.id);
    if (status?.status !== "complete" || rows === 0 || missing !== 0) {
      inconsistent += 1;
    }
  })();
  Atomics.wait(pause, 0, 0, 1);
}
process.stdout.write(`${JSON.stringify({ checks, inconsistent, generations: [...generations] })}\n`);
