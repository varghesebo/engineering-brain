import type Database from "better-sqlite3";

/** Test-file DISCOVERY only: which test files statically import a file (proven edge) or share its name (heuristic). It never says a test covers or exercises behaviour. */
export const TEST_PATH = /(^|\/)(__tests__|__test__|tests?|specs?)\/|\.(test|spec)\.[cm]?[jt]sx?$/i;

export interface TestReference {
  path: string;
  basis: "imports_target" | "imports_through_chain" | "name_match";
  /** Import hops from the test file to the target (0 for a name match). */
  distance: number;
  /** `resolved` for static import edges; `heuristic` for a name match. */
  certainty: "resolved" | "heuristic";
}

const MAX_CHAIN_DEPTH = 3;
const MAX_VISITED = 2000;

const stemOf = (path: string): string => (path.split("/").pop() ?? "").replace(/\.(test|spec)(?=\.)/i, "").replace(/\.[^.]+$/, "").toLowerCase();

export function findTestsFor(db: Database.Database, generationId: number, targetPath: string, limit = 20): TestReference[] {
  const found = new Map<string, TestReference>();
  const seen = new Set<string>([targetPath]);
  let frontier = [targetPath];
  const reverse = db.prepare(
    "SELECT DISTINCT src_path AS path FROM graph_edges INDEXED BY idx_graph_edges_dst WHERE generation_id = ? AND family = 'module' AND edge_kind IN ('IMPORTS','RE_EXPORTS') AND resolution = 'resolved' AND dst_kind = 'file' AND dst_path = ? AND src_kind = 'file' LIMIT 500"
  );
  for (let distance = 1; distance <= MAX_CHAIN_DEPTH && frontier.length > 0 && seen.size < MAX_VISITED; distance += 1) {
    const next: string[] = [];
    for (const path of frontier) {
      for (const row of reverse.all(generationId, path) as Array<{ path: string }>) {
        if (seen.has(row.path)) {
          continue;
        }
        seen.add(row.path);
        if (TEST_PATH.test(row.path)) {
          found.set(row.path, { path: row.path, basis: distance === 1 ? "imports_target" : "imports_through_chain", distance, certainty: "resolved" });
        } else {
          next.push(row.path); // a barrel or helper between the test and the target
        }
      }
    }
    frontier = next;
  }
  const stem = stemOf(targetPath);
  if (stem.length >= 3) {
    const rows = db.prepare("SELECT path FROM generation_files WHERE generation_id = ? AND content_hash IS NOT NULL AND path LIKE ? ESCAPE '\\' LIMIT 200")
      .all(generationId, `%${stem.replace(/[\\%_]/g, (c) => `\\${c}`)}%`) as Array<{ path: string }>;
    for (const row of rows) {
      if (!found.has(row.path) && TEST_PATH.test(row.path) && stemOf(row.path) === stem) {
        found.set(row.path, { path: row.path, basis: "name_match", distance: 0, certainty: "heuristic" });
      }
    }
  }
  const order = { imports_target: 0, imports_through_chain: 1, name_match: 2 } as const;
  return [...found.values()].sort((a, b) => order[a.basis] - order[b.basis] || a.distance - b.distance || (a.path < b.path ? -1 : 1)).slice(0, limit);
}
