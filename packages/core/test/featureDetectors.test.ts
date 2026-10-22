import { describe, expect, it } from "vitest";
import { detectOpenApi, detectScript, detectSql, normalizePath, sqlTables } from "../src/features/detectors.js";
import { lexScript } from "../src/features/lexer.js";

const by = (source: string, role: string) => detectScript(source).filter((e) => e.role === role);

describe("normalizePath", () => {
  it("collapses parameter spellings and drops query, fragment and trailing slash", () => {
    expect(normalizePath("/users/:id/")).toBe("/users/{}");
    expect(normalizePath("/users/{userId}?x=1")).toBe("/users/{}");
    expect(normalizePath("/users/{}/orders/*")).toBe("/users/{}/orders/{}");
    expect(normalizePath("/")).toBe("/");
    expect(normalizePath("//a//b")).toBe("/a/b");
  });
});

describe("lexer", () => {
  it("ignores comments, strings and regex literals that look like code, and survives an apostrophe in JSX text", () => {
    const src = [
      "// app.get('/commented', handler)",
      "/* app.post('/block', h) */",
      "const s = \"app.get('/instring', h)\";",
      "const r = /app\\.get\\('\\/re', h\\)/;",
      "const el = <p>don't break</p>;",
      "app.get('/real', realHandler, other);"
    ].join("\n");
    expect(by(src, "server_route").map((e) => e.key)).toEqual(["GET /real"]);
  });
  it("reports template literals with substitutions as dynamic and bounds the token count", () => {
    const { tokens } = lexScript("const u = `/api/${id}/x`;");
    expect(tokens.find((t) => t.t === "tpl")).toMatchObject({ v: "/api/{}/x", dyn: true });
    expect(lexScript("a;".repeat(300_000)).truncated).toBe(true);
  });
});

describe("HTTP routes and clients", () => {
  it("detects server routes with inline, referenced and middleware handlers; dynamic paths are explicitly unknown", () => {
    const src = [
      "app.get('/api/users/:id', (req, res) => res.json({}));",
      "router.post('/api/users', auth, createUser);",
      "app.delete(`/api/users/${'x'}`, h => h);",
      "app.get(prefix + '/dyn', handler2);",
      "app.use('/v1', v1Router);"
    ].join("\n");
    const routes = by(src, "server_route");
    expect(routes.map((r) => [r.method, r.key, r.handler, r.dynamic])).toEqual([
      ["GET", "GET /api/users/{}", null, false], ["POST", "POST /api/users", "createUser", false], ["DELETE", "DELETE /api/users/{}", null, false], ["GET", null, "handler2", true]
    ]);
    expect(by(src, "mount").map((m) => [m.target, m.handler])).toEqual([["/v1", "v1Router"]]);
  });
  it("detects NestJS decorator routes with the controller prefix", () => {
    const src = "@Controller('users')\nclass C {\n  @Get(':id')\n  async findOne() {}\n  @Post()\n  create() {}\n}";
    expect(by(src, "server_route").map((r) => [r.key, r.handler])).toEqual([["GET /users/{}", "findOne"], ["POST /users", "create"]]);
  });
  it("detects client calls (fetch with a method, axios, dynamic urls) and does not call a single-argument getter on a server a route", () => {
    const src = [
      "fetch('/api/users');",
      "fetch('/api/users', { method: 'POST', body: x });",
      "fetch(url);",
      "axios.get('/api/orders/' + id);",
      "axios.put(`/api/orders/${id}`, data);",
      "cache.get('/not-a-server');"
    ].join("\n");
    const calls = by(src, "client_call");
    expect(calls.map((c) => [c.method, c.key, c.dynamic])).toEqual([
      ["GET", "GET /api/users", false], ["POST", "POST /api/users", false], ["GET", null, true], ["GET", null, true], ["PUT", "PUT /api/orders/{}", false], ["GET", "GET /not-a-server", false]
    ]);
    expect(calls[5]!.attrs).toMatchObject({ knownClient: false }); // a weak hint, flagged
    expect(by(src, "server_route")).toEqual([]);
  });
});

describe("events, jobs, UI routes, SQL, tests and OpenAPI", () => {
  it("detects producers and consumers with literal names, queue workers, and dynamic names as unknown", () => {
    const src = [
      "emitter.emit('user.created', u);",
      "bus.on('user.created', onCreated);",
      "queue.add('send-email', payload);",
      "new Worker('emails', processEmail);",
      "events.publish(name, x);",
      "socket.on('click', () => 1);",
      "a.on('error', fn);",
      "process.on('exit', fn);",
      "eventTypes.add('click');",
      "new Worker('./w.js', opts);"
    ].join("\n");
    const events = detectScript(src).filter((e) => e.kind === "event");
    expect(events.map((e) => [e.role, e.key, e.handler])).toEqual([
      ["event_producer", "user.created", null], ["event_consumer", "user.created", "onCreated"], ["event_producer", "send-email", null], ["event_consumer", "emails", "processEmail"]
    ]); // Node/DOM events (`a.on("error")`, `process.on`, `socket.on("click")`), a worker_threads Worker, a non-messaging receiver with a dynamic name and `eventTypes.add` are NOT application events
  });
  it("detects scheduled jobs, JSX and object UI routes", () => {
    const src = [
      "cron.schedule('*/5 * * * *', cleanup);",
      "<Route path=\"/users/:id\" element={<UserPage />} />;",
      "const routes = [{ path: '/orders', element: <Orders /> }, { path: '/legacy', component: Legacy }];"
    ].join("\n");
    expect(by(src, "job").map((j) => [j.key, j.handler])).toEqual([["*/5 * * * *", "cleanup"]]);
    expect(by(src, "ui_route").map((r) => [r.key, r.handler])).toEqual([["/users/{}", "UserPage"], ["/orders", "Orders"], ["/legacy", "Legacy"]]);
  });
  it("extracts tables and access from SQL text, DDL and code strings, and prisma model access", () => {
    expect(sqlTables("SELECT u.id FROM users u JOIN orders o ON o.uid = u.id WHERE 1")).toEqual([{ table: "orders", access: "read" }, { table: "users", access: "read" }]);
    expect(sqlTables("INSERT INTO audit_log (a) VALUES (1)")).toEqual([{ table: "audit_log", access: "write" }]);
    expect(sqlTables("UPDATE users SET name = 1; DELETE FROM sessions")).toEqual([{ table: "sessions", access: "write" }, { table: "users", access: "write" }]);
    const ddl = detectSql("-- CREATE TABLE ignored (x int);\nCREATE TABLE IF NOT EXISTS public.users (id int);\n/* CREATE TABLE hidden (x) */\nINSERT INTO users (id) VALUES (1);");
    expect(ddl.filter((e) => e.role === "ddl_table").map((e) => e.key)).toEqual(["public.users"]); // schema-qualified names stay qualified
    expect(ddl.filter((e) => e.role === "sql_query").map((e) => e.attrs?.["tables"])).toEqual([["write:users"]]);
    const code = detectScript("const q = 'SELECT * FROM users WHERE id = ?'; await prisma.invoice.findMany({}); const m = 'select the best';");
    expect(code.filter((e) => e.kind === "db_query").map((e) => (e.attrs?.["tables"] as string[]).join()).sort()).toEqual(["read:invoice", "read:users"]);
  });
  it("detects test cases and OpenAPI JSON operations", () => {
    expect(by("describe('users api', () => { it('lists users', () => {}); });", "test_case").map((t) => t.key)).toEqual(["users api", "lists users"]);
    const spec = JSON.stringify({ openapi: "3.0.0", paths: { "/users/{id}": { get: { operationId: "getUser" }, parameters: [] }, "/users": { post: {} } } });
    expect(detectOpenApi(spec).map((o) => [o.key, o.attrs?.["operationId"]])).toEqual([["GET /users/{}", "getUser"], ["POST /users", null]]);
    expect(detectOpenApi("{\"name\": \"not a spec\"}")).toEqual([]);
    expect(detectOpenApi("not json")).toEqual([]);
  });
});

describe("review regressions: detectors", () => {
  const clients = (src: string) => detectScript(src).filter((e) => e.role === "client_call");
  const routes = (src: string) => detectScript(src).filter((e) => e.role === "server_route");

  it("fetch: the method is known only when the options say so; anything else is an UNKNOWN method, never a guessed GET", () => {
    const src = [
      "fetch('/a');", "fetch('/b', opts);", "fetch('/c', { ...opts });", "fetch('/d', { method: cond ? 'POST' : 'GET' });", "fetch('/e', { headers: {} });", "fetch('/f', { method: 'post' });"
    ].join("\n");
    expect(clients(src).map((c) => [c.key, c.attrs?.["methodUnknown"] === true])).toEqual([
      ["GET /a", false], ["ANY /b", true], ["ANY /c", true], ["ANY /d", true], ["GET /e", false], ["POST /f", false]
    ]);
  });

  it("NestJS: a non-literal controller prefix is unknown, the prefix does not leak to the next class, and the handler skips other decorators", () => {
    expect(routes("@Controller({ path: 'admin' })\nclass A {\n  @Get('users') list() {}\n}").map((r) => r.key)).toEqual(["GET /admin/users"]);
    const unknown = routes("@Controller(PREFIX)\nclass A {\n  @Get('users') list() {}\n}");
    expect(unknown.map((r) => [r.key, r.dynamic])).toEqual([[null, true]]);
    expect(routes("@Controller('a')\nclass A {\n  @Get('x') one() {}\n}\nclass B {\n  @Get('y') two() {}\n}").map((r) => r.key)).toEqual(["GET /a/x"]);
    expect(routes("@Controller('c')\nclass A {\n  @Get()\n  @UseGuards(AuthGuard)\n  async findAll() {}\n}").map((r) => r.handler)).toEqual(["findAll"]);
  });

  it("templates with an unknown leading part are dynamic, not a known path", () => {
    expect(routes("const app = express();\napp.get(`${BASE}/users`, h);").map((r) => [r.key, r.dynamic])).toEqual([[null, true]]);
    expect(clients("fetch(`${base}/x`);").map((c) => [c.key, c.dynamic])).toEqual([[null, true]]);
    expect(routes("const app = express();\napp.get(`/users/${id}`, h);").map((r) => r.key)).toEqual(["GET /users/{}"]);
  });

  it("receivers: only server-shaped receivers are routes; loggers, parsers, users and API clients with callbacks are not", () => {
    const src = ["logger.get('/health', cb);", "parser.post('/x', cb);", "user.get('/me', cb);", "api.get('/users', (res) => res);", "const users = Router();", "users.get('/a', h);", "adminRouter.get('/b', h);"].join("\n");
    expect(routes(src).map((r) => r.key)).toEqual(["GET /a", "GET /b"]);
  });

  it("SQL: prose that merely contains SQL words is not SQL", () => {
    const code = detectScript([
      "const a = 'Select one item from the list below';", "const b = 'Delete from cart is not allowed';", "const c = 'Please select a row from users to continue';", "const d = 'extract(year from created_at) is used here';",
      "const real = 'SELECT id FROM users WHERE id = 1';", "const real2 = 'DELETE FROM sessions WHERE expired = 1';", "const ok = 'select a.id from accounts a join b on a.id = b.id';"
    ].join("\n"));
    expect(code.filter((e) => e.kind === "db_query").map((e) => e.name).sort()).toEqual(["delete sessions", "select accounts, b", "select users"].sort());
  });

  it("lines stay correct after backslash-newline continuations and escaped template newlines; JSX closing tags do not hide later code", () => {
    const src = "const s = \"a\\\nb\";\nconst t = `x\\\ny`;\nconst app = express();\napp.get('/five', h);";
    expect(routes(src)[0]!.startLine).toBe(6); // string lines 1-2, template lines 3-4, express on 5, the route on 6
    const jsx = "const l = <ul><li>a</li><li>b</li></ul>;\nconst app = express();\napp.get('/after', h);\nconst r = <div></div><Route path=\"/c\" element={<C />} />;";
    expect(routes(jsx).map((r) => r.key)).toEqual(["GET /after"]);
    expect(detectScript(jsx).filter((e) => e.role === "ui_route").map((r) => r.key)).toEqual(["/c"]);
  });

  it("URLs are stored without query string or credentials; external hosts are flagged", () => {
    const [c] = clients("fetch('https://user:pw@api.example.com/v1/x?access_token=SECRET#frag');");
    expect(JSON.stringify(c)).not.toMatch(/SECRET|pw@|access_token/);
    expect(c!.attrs).toMatchObject({ host: "api.example.com", external: true });
    expect(clients("fetch('http://localhost:3000/api/x');")[0]!.attrs).toMatchObject({ external: false });
  });

  it("scans are linear: a large SQL file and unclosed calls stay fast, and limits are reported as coverage notes", () => {
    const sql = `${"SELECT 1;\n".repeat(60_000)}${"INSERT INTO t (a) VALUES (1);\n".repeat(3000)}`;
    let t0 = Date.now();
    const found = detectSql(sql);
    expect(Date.now() - t0).toBeLessThan(3000);
    expect(found.filter((e) => e.role === "sql_query").length).toBeLessThanOrEqual(3000);
    t0 = Date.now();
    detectScript("app.get(".repeat(125_000));
    detectScript("@Get(".repeat(100_000));
    expect(Date.now() - t0).toBeLessThan(4000);
    const many = Array.from({ length: 3200 }, (_, i) => `app.get("/r${i}", h);`).join("\n");
    expect(detectScript(`const app = express();\n${many}`).some((e) => e.role === "coverage_note" && e.attrs?.["reason"] === "entity_limit")).toBe(true);
    expect(detectScript("a;".repeat(300_000)).some((e) => e.role === "coverage_note" && e.attrs?.["reason"] === "token_limit")).toBe(true);
  });
});
