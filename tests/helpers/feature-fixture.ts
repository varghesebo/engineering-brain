/**
 * The five-service synthetic fixture: web (UI routes + API calls), api (HTTP routes, events, SQL), worker (event consumer, SQL), db (migrations), with a test.
 * Deliberately incomplete in known places: a UI call to a route that does not exist, a dynamic route, a dynamic fetch URL, an event nobody consumes.
 */
export function featureFiles(): Record<string, string> {
  return {
    "package.json": JSON.stringify({ name: "acme", private: true, workspaces: ["services/*"] }),
    "services/web/package.json": JSON.stringify({ name: "@acme/web" }),
    "services/api/package.json": JSON.stringify({ name: "@acme/api" }),
    "services/worker/package.json": JSON.stringify({ name: "@acme/worker" }),
    "services/db/package.json": JSON.stringify({ name: "@acme/db" }),
    "services/web/src/App.tsx": [
      "import { UsersPage } from \"./pages/UsersPage\";",
      "import { OrderPage } from \"./pages/OrderPage\";",
      "export const App = () => (",
      "  <Routes>",
      "    <Route path=\"/users\" element={<UsersPage />} />",
      "    <Route path=\"/orders/:id\" element={<OrderPage />} />",
      "  </Routes>",
      ");"
    ].join("\n"),
    "services/web/src/pages/UsersPage.tsx": [
      "export function UsersPage() {",
      "  fetch(\"/api/users\");",
      "  fetch(window.location.search);",
      "  return null;",
      "}"
    ].join("\n"),
    "services/web/src/pages/OrderPage.tsx": "import axios from \"axios\";\nexport function OrderPage(props: { id: string }) {\n  axios.get(`/api/orders/${props.id}`);\n  return null;\n}\n",
    "services/api/src/server.ts": [
      "import express from \"express\";",
      "import { router as usersRouter } from \"./routes/users\";",
      "const app = express();",
      "const prefix = process.env.PREFIX;",
      "app.use(\"/api\", usersRouter);",
      "app.get(prefix + \"/dynamic\", dynamicHandler);",
      "function dynamicHandler() {}"
    ].join("\n"),
    "services/api/src/routes/users.ts": [
      "import express from \"express\";",
      "import { listUsers } from \"../handlers/users\";",
      "export const router = express.Router();",
      "router.get(\"/users\", listUsers);",
      "router.post(\"/users\", createUser);",
      "function createUser(req: any, res: any) {",
      "  db.query(\"INSERT INTO users (name) VALUES (?)\", [req.body.name]);",
      "  bus.emit(\"user.created\", req.body);",
      "}"
    ].join("\n"),
    "services/api/src/handlers/users.ts": [
      "export function listUsers(req: any, res: any) {",
      "  const rows = db.query(\"SELECT id, name FROM users\");",
      "  queue.publish(\"user.listed\", { n: rows.length });",
      "  queue.publish(\"user.deleted\", {});",
      "  res.json(rows);",
      "}"
    ].join("\n"),
    "services/api/test/users.test.ts": "import { router } from \"../src/routes/users\";\ndescribe(\"users api\", () => {\n  it(\"lists users\", () => { void router; });\n});\n",
    "services/worker/src/consumer.ts": [
      "export function onListed(msg: unknown) {",
      "  db.query(\"INSERT INTO audit_log (event) VALUES (?)\", [msg]);",
      "}",
      "queue.subscribe(\"user.listed\", onListed);"
    ].join("\n"),
    "services/db/migrations/001_init.sql": "CREATE TABLE users (id integer primary key, name text);\nCREATE TABLE audit_log (id integer primary key, event text);\n"
  };
}
