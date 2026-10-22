import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { approveClaim, featureImpact, indexRepository, listClaims, listFeatures, rebindClaim, retireClaim, submitCandidates, traceFrom } from "@engbrain/core";
import { afterAll, describe, expect, it } from "vitest";
import { cleanupTempDirs, engbrainHome, git, makeGitRepo, openFor, runCli } from "../helpers/env.js";
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
  const repo = makeGitRepo({ "package.json": JSON.stringify({ name: "r", workspaces: ["svc/*"] }), ...files });
  const home = engbrainHome();
  await index(repo, home, true);
  return { repo, home };
}
const rows = <T>(o: Opened, sql: string, ...params: unknown[]): T[] => o.store.db.prepare(`${sql}`).all(...params) as T[];
const cur = "(SELECT current_generation_id FROM store_meta)";

describe("H2 review: false behavioural claims", () => {
  it("C1 a mount prefix applies only to the router actually mounted, never to middleware or other routers in the file", async () => {
    const { repo, home } = await build({
      "src/auth.ts": "export function authMw() {}\nexport const adminRouter = Router();\nadminRouter.get('/secret', h);\nfunction h() {}\n",
      "src/users.ts": "export const users = Router();\nconst other = Router();\nusers.get('/a', h);\nother.get('/b', h);\nfunction h() {}\nexport default users;\n",
      "src/server.ts": "import { authMw } from './auth';\nimport users from './users';\nconst app = express();\napp.use('/api', authMw);\napp.use('/u', users);\n"
    });
    await withStore(repo, home, (o) => {
      const keys = rows<{ key: string }>(o, `SELECT key FROM feature_entities WHERE generation_id = ${cur} AND kind = 'route' ORDER BY key`).map((r) => r.key);
      expect(keys).toEqual(["GET /b", "GET /secret", "GET /u/a"]);
      const gaps = rows<{ kind: string; detail: string }>(o, `SELECT kind, detail FROM feature_gaps WHERE generation_id = ${cur} AND kind = 'mount_target_not_a_router'`);
      expect(gaps.length).toBe(1);
      expect(gaps[0]!.detail).toMatch(/authMw/);
    });
  }, 120_000);

  it("C2 a table defined in another package is not linked 'resolved'; schema-qualified names stay distinct; ORM access is heuristic", async () => {
    const { repo, home } = await build({
      "svc/one/package.json": JSON.stringify({ name: "one" }), "svc/two/package.json": JSON.stringify({ name: "two" }),
      "svc/one/schema.sql": "CREATE TABLE users (id int);\nCREATE TABLE audit.accounts (id int);\nCREATE TABLE public.accounts (id int);\n",
      "svc/two/q.ts": "db.query('SELECT * FROM users');\ndb.query('SELECT * FROM public.accounts');\nprisma.user.findMany({});\n"
    });
    await withStore(repo, home, (o) => {
      const edges = rows<{ relation: string; certainty: string; reason: string; name: string }>(o,
        `SELECT e.relation, e.certainty, e.reason, t.name FROM feature_edges e JOIN feature_entities t ON t.generation_id = e.generation_id AND t.entity_id = e.dst_entity WHERE e.generation_id = ${cur} AND e.relation IN ('READS','WRITES') ORDER BY t.name, e.reason`);
      expect(edges.find((e) => e.name === "users" && e.reason === "table_defined_in_another_package")).toMatchObject({ certainty: "heuristic" });
      expect(edges.find((e) => e.name === "public.accounts")).toMatchObject({ certainty: "heuristic", reason: "table_defined_in_another_package" });
      expect(edges.some((e) => e.name === "audit.accounts")).toBe(false); // the other schema was not touched
      expect(edges.filter((e) => e.certainty === "resolved")).toEqual([]);
      expect(rows<{ certainty: string }>(o, `SELECT e.certainty FROM feature_edges e JOIN feature_entities q ON q.generation_id = e.generation_id AND q.entity_id = e.src_entity WHERE e.generation_id = ${cur} AND q.mechanism = 'orm_pattern'`).every((r) => r.certainty === "heuristic")).toBe(true);
    });
  }, 120_000);

  it("C3 unrelated emitters are not linked; non-messaging receivers only ever give a heuristic link", async () => {
    const { repo, home } = await build({
      "src/a.ts": "a.on('error', fn);\nprocess.on('exit', fn);\n", "src/b.ts": "b.emit('error', e);\n",
      "src/c.ts": "thing.emit('order.created', o);\n", "src/d.ts": "other.on('order.created', h);\n",
      "src/e.ts": "queue.publish('invoice.sent', i);\n", "src/f.ts": "queue.subscribe('invoice.sent', h);\n"
    });
    await withStore(repo, home, (o) => {
      const flows = rows<{ certainty: string; reason: string }>(o, `SELECT certainty, reason FROM feature_edges WHERE generation_id = ${cur} AND relation = 'EVENT_FLOW' ORDER BY certainty`);
      expect(flows).toEqual([{ certainty: "heuristic", reason: "same_event_name_but_a_receiver_is_not_messaging_shaped" }, { certainty: "resolved", reason: "same_event_name_on_messaging_receivers" }]);
      expect(rows<{ key: string }>(o, `SELECT key FROM feature_entities WHERE generation_id = ${cur} AND kind = 'event' AND key = 'error'`)).toEqual([]);
    });
  }, 120_000);

  it("C4/C5/C7 external hosts are not linked to internal routes, weak or unknown-method calls are never 'resolved', parameter segments match as ambiguous", async () => {
    const { repo, home } = await build({
      "src/server.ts": "const app = express();\napp.get('/charges', h);\napp.get('/users/:id', h);\napp.get('/b', h);\napp.post('/b', h);\nfunction h() {}\n",
      "src/web.ts": ["fetch('https://api.stripe.com/charges');", "fetch('/charges');", "fetch('/users/me');", "fetch('/b', opts);", "cache.get('/charges');"].join("\n"),
      "src/web2.ts": "axios.create({ baseURL: '/v2' });\naxios.get('/charges');\n"
    });
    await withStore(repo, home, (o) => {
      const calls = rows<{ certainty: string; reason: string; line: number; path: string }>(o,
        `SELECT e.certainty, e.reason, c.start_line AS line, c.path FROM feature_edges e JOIN feature_entities c ON c.generation_id = e.generation_id AND c.entity_id = e.src_entity WHERE e.generation_id = ${cur} AND e.relation = 'CALLS_API' ORDER BY c.path, c.start_line, e.reason`);
      const at = (path: string, line: number) => calls.filter((c) => c.path === path && c.line === line);
      expect(at("src/web.ts", 1)).toEqual([]); // the call to api.stripe.com is not a call to our /charges route
      expect(at("src/web.ts", 2)).toEqual([{ certainty: "resolved", reason: "exact_method_and_path", line: 2, path: "src/web.ts" }]);
      expect(at("src/web.ts", 3)).toMatchObject([{ certainty: "ambiguous", reason: "path_parameter_segment_match" }]);
      expect(at("src/web.ts", 4).length).toBe(2);
      expect(at("src/web.ts", 4).every((c) => c.certainty === "ambiguous" && c.reason === "several_routes_match")).toBe(true); // an unknown method matches both GET and POST /b
      expect(at("src/web.ts", 5)[0]).toMatchObject({ certainty: "heuristic", reason: "weak_client_signal" });
      expect(at("src/web2.ts", 2)[0]).toMatchObject({ certainty: "heuristic", reason: "base_url_may_differ" }); // a configured baseURL: the real path may differ
      expect(rows(o, `SELECT 1 FROM feature_gaps WHERE generation_id = ${cur} AND kind = 'client_call_without_route'`)).toEqual([]); // /users/me is matched by a parameter segment: no false gap
    });
  }, 120_000);

  it("C10 an imported handler is not mistaken for a same-named class method; C11 only calls inside the component belong to its UI route", async () => {
    const { repo, home } = await build({
      "src/h.ts": "export function getUser() {}\n",
      "src/s.ts": "import { getUser } from './h';\nconst router = Router();\nrouter.get('/x', getUser);\nclass A { getUser() {} }\n",
      "src/App.tsx": "import { Page } from './Page';\nexport const r = <Route path=\"/page\" element={<Page />} />;\n",
      "src/Page.tsx": "export function Page() {\n  fetch('/api/mine');\n}\nexport function Other() {\n  fetch('/api/other');\n}\n"
    });
    await withStore(repo, home, (o) => {
      const h = rows<{ dst: string; reason: string; certainty: string }>(o, `SELECT dst_entity AS dst, reason, certainty FROM feature_edges WHERE generation_id = ${cur} AND relation = 'HANDLES_WITH'`);
      expect(h).toEqual([{ dst: "sym:src/h.ts#getUser", reason: "imported_binding", certainty: "resolved" }]);
      const used = rows<{ key: string; certainty: string; reason: string }>(o, `SELECT c.key, e.certainty, e.reason FROM feature_edges e JOIN feature_entities c ON c.generation_id = e.generation_id AND c.entity_id = e.dst_entity WHERE e.generation_id = ${cur} AND e.relation = 'USES_API_CALL'`);
      expect(used).toEqual([{ key: "GET /api/mine", certainty: "resolved", reason: "call_inside_component_range" }]);
    });
  }, 120_000);

  it("C12 flows follow a request: a shared table or consumer never merges sibling routes into one flow", async () => {
    const { repo, home } = await build({
      "src/s.ts": "const app = express();\napp.get('/billing', billing);\napp.get('/profile', profile);\nfunction billing() { db.query('SELECT * FROM settings'); }\nfunction profile() { db.query('SELECT * FROM settings'); }\n",
      "src/ddl.sql": "CREATE TABLE settings (id int);\n"
    });
    await withStore(repo, home, (o) => {
      const members = (id: string) => rows<{ name: string }>(o, `SELECT e.name FROM feature_members m JOIN feature_entities e ON e.generation_id = m.generation_id AND e.entity_id = m.entity_id WHERE m.generation_id = ${cur} AND m.feature_id = ?`, id).map((r) => r.name);
      expect(members("flow:route:GET /billing")).toContain("settings");
      expect(members("flow:route:GET /billing")).not.toContain("GET /profile");
      expect(members("flow:route:GET /profile")).not.toContain("GET /billing");
    });
  }, 120_000);

  it("C13 Next.js file conventions apply only where `next` is a dependency, and route groups and parallel slots are handled", async () => {
    const without = await build({ "package.json": JSON.stringify({ name: "notnext" }), "pages/a.tsx": "export default function A() {}\n" });
    await withStore(without.repo, without.home, (o) => expect(rows(o, `SELECT 1 FROM feature_entities WHERE generation_id = ${cur} AND kind = 'ui_route'`)).toEqual([]));
    const next = await build({
      "package.json": JSON.stringify({ name: "web", dependencies: { next: "14.0.0" } }),
      "app/(marketing)/about/page.tsx": "export default function P() {}\n", "app/@modal/login/page.tsx": "export default function M() {}\n", "app/blog/[...slug]/page.tsx": "export default function B() {}\n", "pages/api/ping.ts": "export default function h() {}\n"
    });
    await withStore(next.repo, next.home, (o) => {
      const keys = rows<{ key: string }>(o, `SELECT key FROM feature_entities WHERE generation_id = ${cur} AND mechanism = 'file_convention' ORDER BY key`).map((r) => r.key);
      expect(keys).toEqual(["/about", "/blog/{}", "ANY /api/ping"]);
    });
  }, 120_000);
});

describe("H2 review: identity, branches and stability", () => {
  const serviceRoutes = (path: string): Record<string, string> => ({
    "svc/one/package.json": JSON.stringify({ name: "one" }), "svc/two/package.json": JSON.stringify({ name: "two" }),
    "svc/one/r.ts": `const app = express();\napp.get('${path}', h);\nfunction h() {}\n`, "svc/two/r.ts": "const app = express();\napp.get('/dup', h);\nfunction h() {}\n"
  });

  it("C14 the same route in two services has two distinct, service-qualified feature ids; removing one does not re-point the other", async () => {
    const { repo, home } = await build(serviceRoutes("/dup"));
    const ids = await withStore(repo, home, (o) => listFeatures(o.store.db).features.map((f) => f.id));
    expect(ids).toEqual(["flow:route:GET /dup@svc/one", "flow:route:GET /dup@svc/two"]);
    writeFileSync(join(repo, "svc/one/r.ts"), "const app = express();\n");
    await index(repo, home);
    await withStore(repo, home, (o) => {
      expect(listFeatures(o.store.db).features.map((f) => f.id)).toEqual(["flow:route:GET /dup@svc/two"]); // svc/two keeps its own identity
      expect(rows<{ kind: string; o: string }>(o, `SELECT kind, old_ids_json AS o FROM feature_lineage WHERE generation_id = ${cur}`)).toEqual([{ kind: "removed", o: JSON.stringify(["flow:route:GET /dup@svc/one"]) }]);
      const t = traceFrom(o.store.db, "route:GET /dup");
      expect(t.alsoMatched).toEqual([]);
    });
    const both = await build(serviceRoutes("/dup"));
    await withStore(both.repo, both.home, (o) => {
      const t = traceFrom(o.store.db, "route:GET /dup");
      expect(t.alsoMatched).toHaveLength(1); // the ambiguity is reported, not hidden
      expect(t.note).toMatch(/matched 2 entities/);
    });
  }, 180_000);

  it("C15 lineage and validity never mix branches: switching to another branch and back records nothing that did not happen on main", async () => {
    const { repo, home } = await build({ "svc/one/package.json": JSON.stringify({ name: "one" }), "svc/one/r.ts": "const app = express();\napp.get('/old', h);\nfunction h() {}\n" });
    git(repo, ["checkout", "-q", "-b", "other"]);
    writeFileSync(join(repo, "svc/one/r.ts"), "const app = express();\napp.get('/renamed', h);\nfunction h() {}\n");
    commitAll(repo, "rename on other");
    await index(repo, home);
    await withStore(repo, home, (o) => expect(rows(o, `SELECT 1 FROM feature_lineage WHERE generation_id = ${cur}`)).toEqual([])); // first generation on this branch: no predecessor, nothing is claimed
    git(repo, ["checkout", "-q", "main"]);
    await index(repo, home);
    await withStore(repo, home, (o) => {
      expect(rows(o, `SELECT 1 FROM feature_lineage WHERE generation_id = ${cur}`)).toEqual([]); // no "rename" that never happened on main
      expect(rows<{ v: number }>(o, `SELECT valid_from_generation AS v FROM feature_entities WHERE generation_id = ${cur} AND key = 'GET /old'`)).toEqual([{ v: 1 }]); // existed on main since generation 1
    });
  }, 180_000);

  it("C16 entity ids and validity survive unrelated line shifts", async () => {
    const { repo, home } = await build({ "svc/one/package.json": JSON.stringify({ name: "one" }), "svc/one/q.ts": "db.query('SELECT * FROM t');\nconst app = express();\napp.get('/x', h);\nfunction h() {}\n" });
    const before = await withStore(repo, home, (o) => rows<{ entity_id: string; valid_from_generation: number }>(o, `SELECT entity_id, valid_from_generation FROM feature_entities WHERE generation_id = ${cur} ORDER BY entity_id`));
    writeFileSync(join(repo, "svc/one/q.ts"), `// a new comment line\n${"\n".repeat(3)}db.query('SELECT * FROM t');\nconst app = express();\napp.get('/x', h);\nfunction h() {}\n`);
    await index(repo, home);
    const after = await withStore(repo, home, (o) => rows<{ entity_id: string; valid_from_generation: number }>(o, `SELECT entity_id, valid_from_generation FROM feature_entities WHERE generation_id = ${cur} ORDER BY entity_id`));
    expect(after).toEqual(before);
  }, 180_000);

  it("C18/C27 a file past the detection limit reports a gap; identical bytes at a .sql and a .ts path do not poison each other", async () => {
    const many = Array.from({ length: 3200 }, (_, i) => `app.get("/r${i}", h);`).join("\n");
    const bytes = "const app = express();\napp.get('/poison', h);\nfunction h() {}\n";
    const { repo, home } = await build({ "svc/a.ts": `const app = express();\n${many}`, "svc/poison.sql": bytes, "svc/z.ts": bytes });
    await withStore(repo, home, (o) => {
      expect(rows<{ detail: string }>(o, `SELECT detail FROM feature_gaps WHERE generation_id = ${cur} AND kind = 'detection_truncated'`)[0]!.detail).toMatch(/entity_limit/);
      expect(rows<{ path: string }>(o, `SELECT path FROM feature_entities WHERE generation_id = ${cur} AND key = 'GET /poison'`)).toEqual([{ path: "svc/z.ts" }]);
    });
    // the reverse processing order gives the same answer: facts are keyed by content class
    const rev = await build({ "svc/z.ts": bytes, "svc/poison.sql": bytes });
    await withStore(rev.repo, rev.home, (o) => expect(rows<{ path: string }>(o, `SELECT path FROM feature_entities WHERE generation_id = ${cur} AND key = 'GET /poison'`)).toEqual([{ path: "svc/z.ts" }]));
  }, 180_000);
});

describe("H2 review: claims", () => {
  const SETUP = { "svc/one/package.json": JSON.stringify({ name: "one" }), "svc/one/s.ts": "const app = express();\napp.get('/x', h);\nfunction h() {}\n", "svc/one/ddl.sql": "CREATE TABLE users (id int, email text NOT NULL);\n" };
  const routeId = (o: Opened) => (o.store.db.prepare("SELECT entity_id AS id FROM feature_entities WHERE kind = 'route'").get() as { id: string }).id;
  const tableId = (o: Opened) => (o.store.db.prepare("SELECT entity_id AS id FROM feature_entities WHERE kind = 'db_table' AND key = 'users'").get() as { id: string }).id;

  it("C19 approval cannot launder stale evidence: it is refused until the candidate is explicitly re-bound to the current evidence", async () => {
    const { repo, home } = await build(SETUP);
    await withStore(repo, home, (o) => void submitCandidates(o.store.db, [{ statement: "The x route is public.", evidence: [routeId(o)] }], { source: "model", sourceDetail: "local-llm" }));
    writeFileSync(join(repo, "svc/one/s.ts"), "const app = express();\napp.get('/x', h); // changed\nfunction h() {}\n");
    await index(repo, home);
    await withStore(repo, home, (o) => {
      expect(listClaims(o.store.db)[0]!.evidenceStatus).toBe("evidence_changed");
      expect(() => approveClaim(o.store.db, 1, { approvedBy: "alice" })).toThrow(/evidence changed since this claim was proposed/);
      expect(rebindClaim(o.store.db, 1).evidenceStatus).toBe("ok");
      expect(approveClaim(o.store.db, 1, { approvedBy: "alice" }).trust).toBe("approved");
      expect(() => rebindClaim(o.store.db, 1)).toThrow(/only a candidate/);
    });
  }, 180_000);

  it("C20 table evidence goes stale when the DDL changes (and only then), including referenced-only tables", async () => {
    const { repo, home } = await build({ ...SETUP, "svc/one/q.ts": "db.query('SELECT * FROM ghost_table');\n" });
    await withStore(repo, home, (o) => {
      submitCandidates(o.store.db, [{ statement: "users.email is NOT NULL.", evidence: [tableId(o)] }], { source: "human" });
      approveClaim(o.store.db, 1, { approvedBy: "alice" });
    });
    writeFileSync(join(repo, "svc/one/notes.sql"), "-- unrelated file\nCREATE TABLE other (id int);\n");
    await index(repo, home);
    await withStore(repo, home, (o) => expect(listClaims(o.store.db)[0]!.evidenceStatus).toBe("ok")); // an unrelated file did not stale it
    writeFileSync(join(repo, "svc/one/ddl.sql"), "CREATE TABLE users (id int);\n");
    await index(repo, home);
    await withStore(repo, home, (o) => expect(listClaims(o.store.db)[0]!.evidenceStatus).toBe("evidence_changed"));
  }, 180_000);

  it("C22 a bogus proposal cannot squat a statement: different evidence is a different claim; a retired statement can be proposed again", async () => {
    const { repo, home } = await build(SETUP);
    await withStore(repo, home, (o) => {
      const db = o.store.db;
      expect(submitCandidates(db, [{ statement: "Rate limiting protects /x", evidence: ["file:package.json"] }], { source: "model", sourceDetail: "m" }).inserted).toBe(1);
      const human = submitCandidates(db, [{ statement: "rate  limiting PROTECTS /x", evidence: [routeId(o)] }], { source: "human" });
      expect(human).toMatchObject({ inserted: 1, duplicates: 0 });
      expect(listClaims(db).map((c) => c.source)).toEqual(["model", "human"]);
      // the same statement and evidence again, from anywhere, is inert
      expect(submitCandidates(db, [{ statement: "Rate limiting protects /x", evidence: ["file:package.json"] }], { source: "human" })).toMatchObject({ inserted: 0, duplicates: 1 });
      retireClaim(db, 1, { reason: "wrong evidence" });
      expect(submitCandidates(db, [{ statement: "Rate limiting protects /x", evidence: ["file:package.json"] }], { source: "model", sourceDetail: "m" }).inserted).toBe(1);
    });
  }, 180_000);

  it("C29 control characters and invisible formatting characters are refused in claim text, approver and source", async () => {
    const { repo, home } = await build(SETUP);
    await withStore(repo, home, (o) => {
      const db = o.store.db;
      const result = submitCandidates(db, [{ statement: "fine\u001b[31m text" }, { statement: "hidden‮ text here" }, { statement: "tag\u{e0041} chars here" }], { source: "human" });
      expect(result.inserted).toBe(0);
      expect(result.rejected).toHaveLength(3);
      expect(() => submitCandidates(db, [], { source: "model", sourceDetail: "x‮y" })).toThrow(/sourceDetail/);
      submitCandidates(db, [{ statement: "Clean statement about x.", evidence: [routeId(o)] }], { source: "human" });
      expect(() => approveClaim(db, 1, { approvedBy: "bob‮" })).toThrow(/approvedBy/);
    });
  }, 120_000);

  it("C30 an entity or file that does not exist is reported as not found, not invented", async () => {
    const { repo, home } = await build(SETUP);
    await withStore(repo, home, (o) => {
      expect(traceFrom(o.store.db, "file:no/such/file.ts").start).toBeNull();
      expect(traceFrom(o.store.db, "sym:svc/one/s.ts#nothing").start).toBeNull();
      expect(featureImpact(o.store.db, { symbol: "svc/one/s.ts#nohash" }).found).toBe(false);
      expect(featureImpact(o.store.db, { file: "no/such.ts" }).found).toBe(false);
      expect(featureImpact(o.store.db, { file: "svc/one/s.ts" }).found).toBe(true);
    });
    expect((await runCli(repo, ["feature", "trace", "file:no/such/file.ts"], home)).code).not.toBe(0);
    expect((await runCli(repo, ["feature", "impact", "--file", "no/such.ts"], home)).code).not.toBe(0);
  }, 120_000);
});
