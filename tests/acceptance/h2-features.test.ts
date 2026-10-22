import { cpSync, mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  approveClaim, featureImpact, featureProvenance, indexRepository, listClaims, listFeatures, listGaps, loadAnnotations, resolveAnnotations, showFeature, submitCandidates, traceFrom, validateFeatureGraph
} from "@engbrain/core";
import { installNetworkGuard } from "@engbrain/security";
import { afterAll, describe, expect, it } from "vitest";
import { cleanupTempDirs, engbrainHome, git, makeGitRepo, openFor, runCli, tempDir } from "../helpers/env.js";
import { featureFiles } from "../helpers/feature-fixture.js";
import { commitAll } from "../helpers/dag-fixture.js";

afterAll(cleanupTempDirs);

type Opened = Awaited<ReturnType<typeof openFor>>;
async function withStore<T>(repo: string, home: string, fn: (o: Opened) => Promise<T> | T, init = false): Promise<T> {
  const o = await openFor(repo, home, init);
  try {
    return await fn(o);
  } finally {
    o.close();
  }
}
const index = (repo: string, home: string, init = false) => withStore(repo, home, (o) => indexRepository({ store: o.store, git: o.info, hardenedGit: o.git }), init);
async function build(files: Record<string, string>): Promise<{ repo: string; home: string }> {
  const repo = makeGitRepo(files);
  const home = engbrainHome();
  await index(repo, home, true);
  return { repo, home };
}

/** The feature graph of the current generation as comparable data (no generation ids, no validity bookkeeping). */
function projection(o: Opened): unknown {
  const db = o.store.db;
  const g = (db.prepare("SELECT current_generation_id AS g FROM store_meta").get() as { g: number }).g;
  const q = (sql: string): unknown[] => db.prepare(sql).all(g);
  return {
    entities: q("SELECT entity_id, kind, role, key, name, path, start_line, end_line, package_dir, mechanism, certainty, trust, content_hash, attrs_json FROM feature_entities WHERE generation_id = ? ORDER BY entity_id"),
    edges: q("SELECT src_entity, dst_entity, relation, certainty, mechanism, reason, evidence_path, evidence_line, attrs_json FROM feature_edges WHERE generation_id = ? ORDER BY edge_id"),
    gaps: q("SELECT kind, entity_id, path, line, detail FROM feature_gaps WHERE generation_id = ? ORDER BY gap_id"),
    features: q("SELECT feature_id, name, root_entity, member_count, summary_json FROM features WHERE generation_id = ? ORDER BY feature_id"),
    members: q("SELECT feature_id, entity_id, role, hops FROM feature_members WHERE generation_id = ? ORDER BY feature_id, entity_id")
  };
}

const ROUTES_FILE = "services/api/src/routes/users.ts";
const routesWith = (body: string[]): string => ["import express from \"express\";", "import { listUsers } from \"../handlers/users\";", "export const router = express.Router();", ...body].join("\n");

describe("H2-1 the five-service fixture", () => {
  it("links UI route -> API -> event -> consumer -> table with a test, and reports what it could not decide", async () => {
    const { repo, home } = await build(featureFiles());
    await withStore(repo, home, (o) => {
      const db = o.store.db;
      const list = listFeatures(db);
      expect(list.features.map((f) => f.id)).toEqual(["flow:route:GET /api/users@services/api", "flow:route:POST /api/users@services/api", "flow:ui_route:/orders/{}@services/web", "flow:ui_route:/users@services/web"]);
      const flow = list.features.find((f) => f.id === "flow:route:GET /api/users@services/api")!;
      expect(flow.services).toEqual(["services/api", "services/db", "services/web", "services/worker"]); // four services plus the database package
      expect(flow.trust).toBe("discovered");
      const detail = showFeature(db, "flow:route:GET /api/users@services/api");
      const names = detail.members.map((m) => `${m.kind}:${m.name}`);
      for (const expected of ["route:GET /api/users", "symbol:listUsers", "api_call:GET /api/users", "ui_route:ui /users", "db_query:select users", "db_table:users", "event:user.listed", "symbol:onListed", "db_query:insert audit_log", "db_table:audit_log", "test:services/api/test/users.test.ts"]) {
        expect(names, expected).toContain(expected);
      }
      // entity- and edge-level certainty
      const dynamicRoute = db.prepare("SELECT certainty FROM feature_entities WHERE kind = 'route' AND key IS NULL").get();
      expect(dynamicRoute).toEqual({ certainty: "dynamic_unknown" });
      const edge = (rel: string) => db.prepare("SELECT certainty, reason FROM feature_edges WHERE relation = ? ORDER BY edge_id LIMIT 1").get(rel);
      expect(edge("CALLS_API")).toEqual({ certainty: "resolved", reason: "exact_method_and_path" });
      expect(edge("EVENT_FLOW")).toEqual({ certainty: "resolved", reason: "same_event_name_on_messaging_receivers" });
      expect(edge("TESTS")).toMatchObject({ certainty: "resolved", reason: "test_imports_the_file" });
      // mounts: the router is served under /api although the literal in the router file is /users
      expect(db.prepare("SELECT json_extract(attrs_json, '$.mountedAt') AS m FROM feature_entities WHERE kind = 'route' AND key = 'GET /api/users'").get()).toEqual({ m: "/api" });
      // the gaps are explicit, never silent
      const kinds = listGaps(db).gaps.map((g) => g.kind).sort();
      expect(kinds).toEqual(["client_call_without_route", "dynamic_client_call", "dynamic_route", "event_without_consumer", "event_without_consumer"]);
      expect(listGaps(db, { kind: "client_call_without_route" }).gaps[0]!.detail).toMatch(/GET \/api\/orders\/\{\}/);
      expect(validateFeatureGraph(db)).toEqual({ ok: true, problems: [] });
      // provenance: mechanism, certainty, source hash and validity for every member
      const prov = featureProvenance(db, "flow:route:GET /api/users@services/api");
      expect(prov.found).toBe(true);
      expect(prov.members.filter((m) => m.kind !== "db_table").every((m) => m.mechanism !== null && m.contentHash !== null && m.validFromGeneration === prov.generationId)).toBe(true);
      expect(prov.sourceFingerprint).toEqual(expect.any(String));
    });
  }, 120_000);

  it("trace follows edges both ways within bounds and carries the gaps it meets; impact names the features a file belongs to", async () => {
    const { repo, home } = await build(featureFiles());
    await withStore(repo, home, (o) => {
      const t = traceFrom(o.store.db, "route:GET /api/users", { depth: 4 });
      expect(t.start?.name).toBe("GET /api/users");
      expect(t.nodes.map((n) => n.kind)).toEqual(expect.arrayContaining(["ui_route", "api_call", "event", "db_table", "test", "symbol"]));
      expect(t.gaps.map((g) => g.kind)).toContain("event_without_consumer");
      expect(traceFrom(o.store.db, "route:GET /nope").start).toBeNull();
      const impact = featureImpact(o.store.db, { file: "services/api/src/handlers/users.ts" });
      expect(impact.features.map((f) => f.id)).toContain("flow:route:GET /api/users@services/api");
      expect(impact.disclaimer).toMatch(/POTENTIAL STRUCTURAL/);
      expect(featureImpact(o.store.db, { symbol: "services/api/src/handlers/users.ts#listUsers" }).features.map((f) => f.id)).toContain("flow:route:GET /api/users@services/api");
    });
  }, 120_000);
});

describe("H2-2 editing, branches and rebuild equality", () => {
  it("editing a backend route updates the relationships and reports the rename", async () => {
    const { repo, home } = await build(featureFiles());
    writeFileSync(join(repo, ROUTES_FILE), readRoutes().replace("router.get(\"/users\", listUsers)", "router.get(\"/members\", listUsers)"));
    await index(repo, home);
    await withStore(repo, home, (o) => {
      const db = o.store.db;
      const ids = listFeatures(db).features.map((f) => f.id);
      expect(ids).toContain("flow:route:GET /api/members@services/api");
      expect(ids).not.toContain("flow:route:GET /api/users@services/api");
      expect(listGaps(db, { kind: "client_call_without_route" }).gaps.map((g) => g.detail).join(" ")).toMatch(/GET \/api\/users/); // the UI call lost its route
      const events = db.prepare("SELECT kind, old_ids_json AS o, new_ids_json AS n FROM feature_lineage ORDER BY id").all() as Array<{ kind: string; o: string; n: string }>;
      expect(events).toEqual([{ kind: "renamed", o: JSON.stringify(["flow:route:GET /api/users@services/api"]), n: JSON.stringify(["flow:route:GET /api/members@services/api"]) }]);
      // validity: unchanged entities keep their original generation, the new route starts now
      const rows = db.prepare("SELECT key, valid_from_generation AS v FROM feature_entities WHERE kind = 'route' AND key IS NOT NULL ORDER BY key").all() as Array<{ key: string; v: number }>;
      expect(rows.find((r) => r.key === "POST /api/users")!.v).toBe(1);
      expect(rows.find((r) => r.key === "GET /api/members")!.v).toBe(2);
    });
  }, 120_000);

  it("a feature graph built incrementally equals a clean rebuild of the same source state", async () => {
    const { repo, home } = await build(featureFiles());
    writeFileSync(join(repo, "services/api/src/handlers/users.ts"), "export function listUsers(req: any, res: any) {\n  const rows = db.query(\"SELECT id FROM users\");\n  res.json(rows);\n}\n");
    await index(repo, home);
    const incremental = await withStore(repo, home, (o) => projection(o));
    const copy = join(tempDir("engbrain-clean-"), "copy");
    cpSync(repo, copy, { recursive: true, filter: (src) => !src.includes(".engineering-brain") });
    const home2 = engbrainHome();
    await index(copy, home2, true);
    const clean = await withStore(copy, home2, (o) => projection(o));
    expect(incremental).toEqual(clean);
  }, 180_000);

  it("other branches are isolated: switching back restores exactly the original graph and the other branch's features are not visible", async () => {
    const { repo, home } = await build(featureFiles());
    const original = await withStore(repo, home, (o) => projection(o));
    git(repo, ["checkout", "-q", "-b", "other"]);
    writeFileSync(join(repo, ROUTES_FILE), readRoutes().replace("router.post(\"/users\", createUser)", "router.post(\"/other\", createUser)"));
    commitAll(repo, "other branch route");
    await index(repo, home);
    await withStore(repo, home, (o) => expect(listFeatures(o.store.db).features.map((f) => f.id)).toContain("flow:route:POST /api/other@services/api"));
    git(repo, ["checkout", "-q", "main"]);
    await index(repo, home);
    await withStore(repo, home, (o) => {
      expect(listFeatures(o.store.db).features.map((f) => f.id)).not.toContain("flow:route:POST /api/other@services/api");
      expect(projection(o)).toEqual(original);
    });
  }, 180_000);
});

function readRoutes(): string {
  return featureFiles()[ROUTES_FILE]!;
}

describe("H2-4 feature identity: rename, split, merge and ambiguity", () => {
  const twoRoutes = (a: string, b: string): Record<string, string> => ({
    ...featureFiles(),
    [ROUTES_FILE]: routesWith([`router.get("${a}", listUsers);`, `router.get("${b}", listUsers);`])
  });
  const lineage = async (repo: string, home: string) => withStore(repo, home, (o) => (o.store.db.prepare("SELECT kind, old_ids_json AS o, new_ids_json AS n, certainty FROM feature_lineage ORDER BY id").all() as Array<{ kind: string; o: string; n: string; certainty: string }>).map((e) => ({ kind: e.kind, old: JSON.parse(e.o) as string[], next: JSON.parse(e.n) as string[], certainty: e.certainty })));

  it("one route served by the same handler becoming two routes is a split (heuristic, never certain)", async () => {
    const { repo, home } = await build(featureFiles());
    writeFileSync(join(repo, ROUTES_FILE), routesWith(["router.get(\"/people\", listUsers);", "router.get(\"/staff\", listUsers);", "router.post(\"/users\", createUser);", "function createUser() {}"]));
    await index(repo, home);
    const events = await lineage(repo, home);
    expect(events).toEqual([{ kind: "split", old: ["flow:route:GET /api/users@services/api"], next: ["flow:route:GET /api/people@services/api", "flow:route:GET /api/staff@services/api"], certainty: "heuristic" }, ...events.filter((e) => e.kind !== "split")]);
  }, 120_000);

  it("two features collapsing into one whose flow contains both old entry-point handlers is a merge", async () => {
    const ab = (extra: string[]): string => ["export function hA() {}", "export function hB() {}", ...extra].join("\n");
    const files = {
      ...featureFiles(),
      "services/api/src/handlers/ab.ts": ab([]),
      [ROUTES_FILE]: ["import express from \"express\";", "import { hA, hB } from \"../handlers/ab\";", "export const router = express.Router();", "router.get(\"/a\", hA);", "router.get(\"/b\", hB);"].join("\n")
    };
    const { repo, home } = await build(files);
    writeFileSync(join(repo, "services/api/src/handlers/ab.ts"), ab(["queue.subscribe(\"ev.a\", hA);", "queue.subscribe(\"ev.b\", hB);"]));
    writeFileSync(join(repo, ROUTES_FILE), ["import express from \"express\";", "export const router = express.Router();", "router.get(\"/ab\", combined);", "function combined() {", "  queue.publish(\"ev.a\", {});", "  queue.publish(\"ev.b\", {});", "}"].join("\n"));
    await index(repo, home);
    const events = await lineage(repo, home);
    const merged = events.find((e) => e.kind === "merged");
    expect(merged).toMatchObject({ old: ["flow:route:GET /api/a@services/api", "flow:route:GET /api/b@services/api"], next: ["flow:route:GET /api/ab@services/api"], certainty: "heuristic" });
    expect(events.map((e) => e.kind)).not.toContain("renamed" as never); // no one-to-one claim was made
  }, 120_000);

  it("an overlap that fits no pattern is reported ambiguous, not guessed", async () => {
    const { repo, home } = await build(twoRoutes("/people", "/staff"));
    writeFileSync(join(repo, ROUTES_FILE), routesWith(["router.get(\"/p2\", listUsers);", "router.get(\"/s2\", listUsers);"]));
    await index(repo, home);
    const events = await lineage(repo, home);
    expect(events.filter((e) => e.kind === "ambiguous").length).toBe(2);
    expect(events.filter((e) => e.kind === "ambiguous").every((e) => e.certainty === "ambiguous" && e.next.length === 2)).toBe(true);
    expect(events.map((e) => e.kind)).not.toContain("renamed" as never);
  }, 120_000);
});

describe("H2-3 claims, annotations and the line between evidence and statements", () => {
  it("a candidate cannot become verified by repetition, by smuggling a trust field, or by a model approving itself; approval needs live evidence and goes stale when it changes", async () => {
    const { repo, home } = await build(featureFiles());
    await withStore(repo, home, (o) => {
      const db = o.store.db;
      const routeId = (db.prepare("SELECT entity_id AS id FROM feature_entities WHERE kind = 'route' AND key = 'GET /api/users'").get() as { id: string }).id;
      const statement = "Listing users also records an audit entry through the worker.";
      const first = submitCandidates(db, [{ statement, evidence: [routeId] }], { source: "model", sourceDetail: "local-llm" });
      expect(first).toMatchObject({ inserted: 1, duplicates: 0 });
      for (let i = 0; i < 50; i += 1) {
        submitCandidates(db, [{ statement: i % 2 === 0 ? statement.toUpperCase() : `  ${statement}  `, evidence: [routeId] }], { source: i % 3 === 0 ? "human" : "model", sourceDetail: "local-llm" });
      }
      const claims = listClaims(db);
      expect(claims).toHaveLength(1);
      expect(claims[0]).toMatchObject({ trust: "candidate", source: "model", evidenceStatus: "ok" });
      expect(claims[0]!.label).toMatch(/INFERRED \/ PROPOSED by a model: not verified/);
      // smuggled fields and unknown evidence are rejected
      const bad = submitCandidates(db, [{ statement: "x is trusted", trust: "approved" }, { statement: "points at nothing", evidence: ["route:0000000000000000"] }, { statement: "no", evidence: [] }, "nope"], { source: "model" });
      expect(bad.inserted).toBe(0);
      expect(bad.rejected.map((r) => r.index)).toEqual([0, 1, 2, 3]);
      expect(() => approveClaim(db, 1, { approvedBy: "local-llm" })).toThrow(/cannot approve its own proposal/);
      // a claim without evidence cannot be approved
      const noEvidence = submitCandidates(db, [{ statement: "No evidence is attached to this statement." }], { source: "human" });
      expect(noEvidence).toMatchObject({ inserted: 1 });
      const noEvidenceId = listClaims(db).find((c) => c.evidence.length === 0)!.id;
      expect(() => approveClaim(db, noEvidenceId, { approvedBy: "alice" })).toThrow(/without source evidence/);
      const approved = approveClaim(db, 1, { approvedBy: "alice" });
      expect(approved).toMatchObject({ trust: "approved", approvedBy: "alice", evidenceStatus: "ok" });
      expect(() => approveClaim(db, 1, { approvedBy: "bob" })).toThrow(/only a candidate/);
    });
    // the evidence changes: the approved claim is flagged, not silently trusted
    writeFileSync(join(repo, ROUTES_FILE), readRoutes().replace("router.get(\"/users\", listUsers)", "router.get(\"/users\", listUsers); // edited"));
    await index(repo, home);
    await withStore(repo, home, (o) => expect(listClaims(o.store.db, { trust: "approved" })[0]!.evidenceStatus).toBe("evidence_changed"));
    writeFileSync(join(repo, ROUTES_FILE), routesWith(["router.post(\"/users\", createUser);", "function createUser() {}"]));
    await index(repo, home);
    await withStore(repo, home, (o) => expect(listClaims(o.store.db, { trust: "approved" })[0]!.evidenceStatus).toBe("evidence_missing"));
  }, 180_000);

  it("manual documentation never replaces live code truth: an annotated member the code lacks stays 'documented but not found' and creates nothing", async () => {
    const { repo, home } = await build({ ...featureFiles(), "README.md": "# Docs\nThe API serves GET /api/ghost and POST /api/phantom.\n" });
    const dir = join(repo, ".engineering-brain", "features");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "users.json"), JSON.stringify({
      schemaVersion: 1,
      features: [{
        id: "user-listing", name: "User listing", description: "Lists users for the web app.",
        members: [{ selector: { kind: "route", key: "GET /api/users" }, role: "entry" }, { selector: { kind: "route", key: "GET /api/ghost" } }, { selector: { symbol: "services/api/src/handlers/users.ts#listUsers" } }, { selector: { kind: "db_query", path: "services/api/src/handlers/users.ts" } }],
        constraints: [{ statement: "Never returns deleted users.", source: "docs/api.md" }]
      }]
    }));
    await withStore(repo, home, (o) => {
      const loaded = loadAnnotations(repo);
      expect(loaded.problems).toEqual([]);
      const before = JSON.stringify(projection(o));
      const [view] = resolveAnnotations(o.store.db, loaded.features);
      expect(view!.trust).toBe("annotation");
      expect(view!.members.map((m) => m.status)).toEqual(["resolved", "documented_but_not_found", "resolved", "resolved"]);
      expect(view!.notFound).toBe(1);
      expect(view!.constraints[0]).toMatchObject({ verified: false });
      expect(JSON.stringify(projection(o))).toBe(before); // no entity, edge or feature was created from the document
      const keys = (o.store.db.prepare("SELECT key FROM feature_entities").all() as Array<{ key: string | null }>).map((r) => r.key);
      expect(keys).not.toContain("GET /api/ghost");
      expect(keys).not.toContain("POST /api/phantom");
    });
  }, 120_000);

  it("annotation files are strictly validated and untrusted: unknown properties, bad ids, traversal selectors, symlinks, oversize and duplicates are ignored with a reason", async () => {
    const { repo, home } = await build(featureFiles());
    const dir = join(repo, ".engineering-brain", "features");
    mkdirSync(dir, { recursive: true });
    const ok = { id: "ok-one", name: "Ok", members: [{ selector: { kind: "route", key: "GET /api/users" } }] };
    writeFileSync(join(dir, "a.json"), JSON.stringify({ schemaVersion: 1, features: [ok, { ...ok, id: "ok-one" }, { ...ok, id: "Bad Id" }, { ...ok, id: "extra", evil: true }, { id: "trav", name: "T", members: [{ selector: { path: "../../etc/passwd" } }] }, { id: "kindonly", name: "K", members: [{ selector: { kind: "route" } }] }, { id: "constraint", name: "C", members: ok.members, constraints: [{ statement: "no source" }] }] }));
    writeFileSync(join(dir, "b.json"), "{ not json");
    writeFileSync(join(dir, "c.json"), JSON.stringify({ schemaVersion: 2, features: [] }));
    writeFileSync(join(dir, "d.json"), JSON.stringify({ schemaVersion: 1, features: [], __proto__x: 1 }));
    writeFileSync(join(dir, "big.json"), JSON.stringify({ schemaVersion: 1, features: [], pad: "x".repeat(70_000) }));
    symlinkSync(join(repo, "package.json"), join(dir, "link.json"));
    const loaded = loadAnnotations(repo);
    expect(loaded.features.map((f) => f.id)).toEqual(["ok-one"]);
    const problems = loaded.problems.map((p) => `${p.file}: ${p.problem}`).join("\n");
    for (const expected of ["duplicate feature id", "id (lowercase", "unknown property", "selector path is invalid", "kind alone selects nothing", "documented source", "b.json: not valid JSON", "c.json: expected", "d.json: expected", "big.json: not a regular file", "link.json: not a regular file"]) {
      expect(problems, expected).toContain(expected);
    }
    // a symlinked annotations DIRECTORY is not followed
    const other = await build(featureFiles());
    const outside = tempDir("engbrain-annot-");
    writeFileSync(join(outside, "x.json"), JSON.stringify({ schemaVersion: 1, features: [ok] }));
    symlinkSync(outside, join(other.repo, ".engineering-brain", "features"));
    expect(loadAnnotations(other.repo).features).toEqual([]);
    expect(loadAnnotations(other.repo).problems[0]!.problem).toMatch(/not a real directory/);
  }, 120_000);
});

describe("H2-5 bounds on high-fanout services and hostile source", () => {
  it("a hub consumed by hundreds of routes stays bounded and reports truncation", async () => {
    const routes: string[] = ["import express from \"express\";", "import { handlers } from \"./h\";", "export const router = express.Router();"];
    const handlers: string[] = [];
    for (let i = 0; i < 300; i += 1) {
      routes.push(`router.get("/r${i}", h${i});`);
      handlers.push(`export function h${i}() {\n  queue.publish("hub.event", {});\n}`);
    }
    routes[1] = `import { ${Array.from({ length: 300 }, (_, i) => `h${i}`).join(", ")} } from "./h";`;
    const started = Date.now();
    const { repo, home } = await build({
      "package.json": JSON.stringify({ name: "hub" }), "src/routes.ts": routes.join("\n"), "src/h.ts": handlers.join("\n"),
      "src/consumer.ts": "export function onHub() {}\nqueue.subscribe(\"hub.event\", onHub);\n"
    });
    expect(Date.now() - started).toBeLessThan(60_000);
    await withStore(repo, home, (o) => {
      const db = o.store.db;
      const consumer = (db.prepare("SELECT entity_id AS id FROM feature_entities WHERE role = 'event_consumer'").get() as { id: string }).id;
      const t = traceFrom(db, consumer, { direction: "reverse", depth: 3 });
      expect(t.truncated.fanout).toBe(true);
      expect(t.nodes.length).toBeLessThan(400);
      expect(listFeatures(db, { limit: 5 }).features).toHaveLength(5);
      expect(listFeatures(db).total).toBe(300);
      const flow = showFeature(db, "flow:route:GET /r0");
      expect(flow.members.length).toBeLessThanOrEqual(200);
      expect(validateFeatureGraph(db).ok).toBe(true);
    });
  }, 180_000);

  it("pathological source (megabyte minified line, nested templates, thousands of route-like calls) is bounded and never crashes indexing", async () => {
    const minified = "a=1;".repeat(250_000);
    const nested = `const x = ${"`${".repeat(30)}1${"}`".repeat(30)};`;
    const many = Array.from({ length: 20_000 }, (_, i) => `app.get("/x${i}", (q, r) => 1);`).join("\n");
    const started = Date.now();
    const { repo, home } = await build({ "a.js": minified, "b.js": nested, "c.js": many.slice(0, 900_000), "d.sql": "CREATE TABLE ".repeat(5000) });
    expect(Date.now() - started).toBeLessThan(120_000);
    await withStore(repo, home, (o) => {
      const routes = (o.store.db.prepare("SELECT COUNT(*) AS n FROM feature_entities WHERE kind = 'route'").get() as { n: number }).n;
      expect(routes).toBeLessThanOrEqual(3000); // the per-file detection cap
      expect(validateFeatureGraph(o.store.db).ok).toBe(true);
    });
  }, 240_000);

  it("control characters and very long literals in route paths cannot break the stored graph or the CLI output", async () => {
    const evil = `/api/${"x".repeat(5000)}\u001b[31m`;
    const { repo, home } = await build({ "package.json": JSON.stringify({ name: "e" }), "src/s.ts": `router.get(${JSON.stringify(evil)}, handler);\nfunction handler() {}\n` });
    const out = await runCli(repo, ["feature", "list"], home);
    expect(out.code).toBe(0);
    // eslint-disable-next-line no-control-regex
    expect(out.stdout).not.toMatch(/\u001b/);
  }, 120_000);
});

describe("H2 CLI and offline", () => {
  it("feature list/show/trace/impact/provenance/gaps/validate work, and every feature command makes zero network attempts", async () => {
    const { repo, home } = await build(featureFiles());
    const guard = installNetworkGuard();
    try {
      for (const args of [
        ["feature", "list"], ["feature", "list", "--json"], ["feature", "show", "flow:route:GET /api/users@services/api"], ["feature", "trace", "route:GET /api/users", "--depth", "3", "--direction", "forward"],
        ["feature", "impact", "--file", "services/api/src/handlers/users.ts"], ["feature", "provenance", "flow:route:GET /api/users@services/api"], ["feature", "gaps"], ["feature", "claims"], ["feature", "validate"]
      ]) {
        const run = await runCli(repo, args, home);
        expect(run.code, `${args.join(" ")}: ${run.stderr}`).toBe(0);
      }
      expect(guard.attempts).toEqual([]);
    } finally {
      guard.uninstall();
    }
    const show = await runCli(repo, ["feature", "show", "flow:route:GET /api/users@services/api"], home);
    expect(show.stdout).toMatch(/candidate grouping, not a business-defined feature/);
    expect((await runCli(repo, ["feature"], home)).code).toBe(2);
    expect((await runCli(repo, ["feature", "bogus"], home)).code).toBe(2);
    expect((await runCli(repo, ["feature", "show", "flow:route:nope"], home)).code).not.toBe(0);
    expect((await runCli(repo, ["feature", "trace", "route:GET /api/users", "--direction", "sideways"], home)).code).toBe(2);
  }, 180_000);

  it("propose / approve / retire through the CLI: candidates are labelled, approval is a human act with --by and --yes, a model cannot approve itself", async () => {
    const { repo, home } = await build(featureFiles());
    const id = await withStore(repo, home, (o) => (o.store.db.prepare("SELECT entity_id AS id FROM feature_entities WHERE kind = 'route' AND key = 'GET /api/users'").get() as { id: string }).id);
    const proposals = join(repo, "..", "proposals.json");
    writeFileSync(proposals, JSON.stringify([{ statement: "Listing users publishes a user.listed event.", evidence: [id] }]));
    const propose = await runCli(repo, ["feature", "propose", "--from-file", proposals, "--source", "model", "--source-detail", "local-llm"], home);
    expect(propose.code).toBe(0);
    expect(propose.stdout).toMatch(/1 recorded as candidates \(inferred\/proposed, NOT verified\)/);
    expect((await runCli(repo, ["feature", "claims"], home)).stdout).toMatch(/INFERRED \/ PROPOSED by a model: not verified/);
    expect((await runCli(repo, ["feature", "approve", "1"], home)).code).toBe(2); // needs --by and --yes
    expect((await runCli(repo, ["feature", "approve", "1", "--by", "local-llm", "--yes"], home)).code).toBe(3); // refused by policy
    const ok = await runCli(repo, ["feature", "approve", "1", "--by", "alice", "--yes"], home);
    expect(ok.code).toBe(0);
    expect(ok.stdout).toMatch(/APPROVED/);
    expect((await runCli(repo, ["feature", "retire", "1", "--reason", "superseded"], home)).stdout).toMatch(/RETIRED/);
    expect((await runCli(repo, ["feature", "retire", "1"], home)).code).toBe(2);
  }, 180_000);
});

