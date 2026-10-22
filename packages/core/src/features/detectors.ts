import { createHash } from "node:crypto";
import type { EntityFact } from "../extractor.js";
import { lexScript, type Token } from "./lexer.js";

export const DETECTOR_LIMITS = { entities: 3000, sqlLength: 4000, text: 300, pathInput: 2000 } as const;

const HTTP_METHODS = new Set(["get", "post", "put", "patch", "delete", "head", "options", "all"]);
const CLIENT_RECEIVERS = /^(axios|http|https|request|client|apiclient|httpclient|\$http|ky|got|superagent|fetcher|api)$/i;
const SERVER_NAMES = /^(app|router|server|fastify|koa|express|routes?)$/i;
const SERVER_SUFFIX = /(Router|Routes|App|Server)$/;
const SERVER_FACTORIES = new Set(["express", "Router", "Fastify", "fastify", "Koa", "Hono", "Elysia"]);
const MESSAGING_NAMES = new Set(["bus", "eventbus", "emitter", "eventemitter", "queue", "producer", "consumer", "channel", "broker", "pubsub", "publisher", "subscriber", "kafka", "amqp", "rabbit", "rabbitmq", "nats", "sns", "sqs"]);
const MESSAGING_SUFFIX = /(Bus|Emitter|Queue|Producer|Consumer|Channel|Broker|PubSub|Publisher|Subscriber)$/;
const NOT_EVENT_SOURCES = new Set(["process", "window", "document", "stream", "socket", "req", "res", "request", "response", "child", "proc", "ws", "el", "element", "button", "input", "form", "target", "this", "self", "worker", "emitterclass"]);
const BUILTIN_EVENTS = new Set(["error", "data", "end", "close", "exit", "connect", "message", "open", "drain", "finish", "readable", "pipe", "unpipe", "listening", "line", "click", "change", "input", "submit", "keydown", "keyup", "load", "unload", "resize", "scroll", "focus", "blur", "ready", "disconnect", "connection", "request", "response", "timeout", "abort", "uncaughtexception", "unhandledrejection", "beforeexit", "sigint", "sigterm"]);
const PRODUCER_METHODS = new Set(["emit", "publish", "sendtoqueue", "produce"]);
const CONSUMER_METHODS = new Set(["on", "once", "addlistener", "subscribe", "consume", "process"]);
const DECORATOR_METHODS: Record<string, string> = { get: "GET", post: "POST", put: "PUT", patch: "PATCH", delete: "DELETE", head: "HEAD", options: "OPTIONS", all: "ANY" };
const PRISMA_READ = new Set(["findmany", "findunique", "findfirst", "count", "aggregate", "groupby", "finduniqueorthrow", "findfirstorthrow"]);
const PRISMA_WRITE = new Set(["create", "createmany", "update", "updatemany", "delete", "deletemany", "upsert"]);
const TEST_CALLS = new Set(["describe", "it", "test"]);
const MODIFIERS = new Set(["async", "public", "private", "protected", "static", "readonly", "override", "abstract"]);

const cap = (s: string | null): string | null => (s === null ? null : s.length > DETECTOR_LIMITS.text ? s.slice(0, DETECTOR_LIMITS.text) : s);

/** `/users/:id`, `/users/{id}`, `/users/${id}` and `/users/*` all denote the same shape: parameters become `{}`; query, fragment and a trailing slash are dropped. */
export function normalizePath(path: string): string {
  const noQuery = (path.slice(0, DETECTOR_LIMITS.pathInput).split(/[?#]/)[0]) ?? "";
  const segments = noQuery.split("/").filter((segment, index, all) => segment !== "" || index === 0 && all.length === 1);
  const mapped = segments.map((segment) => (/^:[\w-]+\??$/.test(segment) || /^\{[^}]*\}$/.test(segment) || segment === "*" || /^\[[^\]]+\]$/.test(segment) ? "{}" : segment.replace(/\{\}/g, "{}")));
  return `/${mapped.join("/")}`.replace(/\/{2,}/g, "/");
}

export const joinPaths = (prefix: string, sub: string): string => normalizePath(`${prefix}/${sub}`);

interface Arg { from: number; to: number } // token index range [from, to)

/** Matching `)` of every `(` in ONE pass (an unclosed call costs nothing extra), instead of rescanning per call. */
function parenPairs(tokens: Token[]): Int32Array {
  const close = new Int32Array(tokens.length).fill(-1);
  const stack: number[] = [];
  for (let i = 0; i < tokens.length; i += 1) {
    const t = tokens[i]!;
    if (t.t === "p") {
      if (t.v === "(") {
        stack.push(i);
      } else if (t.v === ")" && stack.length > 0) {
        close[stack.pop()!] = i;
      }
    }
  }
  return close;
}

function argsOf(tokens: Token[], pairs: Int32Array, open: number): { args: Arg[]; close: number } {
  const close = pairs[open] ?? -1;
  if (close === -1) {
    return { args: [], close: -1 };
  }
  const args: Arg[] = [];
  let depth = 0;
  let from = open + 1;
  for (let i = open + 1; i < close; i += 1) {
    const t = tokens[i]!;
    if (t.t === "p") {
      if (t.v === "(" || t.v === "[" || t.v === "{") {
        depth += 1;
      } else if (t.v === ")" || t.v === "]" || t.v === "}") {
        depth -= 1;
      } else if (t.v === "," && depth === 0) {
        args.push({ from, to: i });
        from = i + 1;
      }
    }
  }
  if (from < close) {
    args.push({ from, to: close });
  }
  return { args, close };
}

type ArgKind = "literal" | "template" | "fn" | "ref" | "object" | "other";

function kindOf(tokens: Token[], a: Arg): ArgKind {
  const first = tokens[a.from];
  if (first === undefined) {
    return "other";
  }
  if (a.to - a.from === 1) {
    if (first.t === "str") {
      return "literal";
    }
    if (first.t === "tpl") {
      return first.dyn === true ? "template" : "literal";
    }
    if (first.t === "id") {
      return first.v === "function" ? "fn" : "ref";
    }
  }
  if (first.t === "id" && (first.v === "function" || first.v === "async")) {
    return "fn";
  }
  for (let i = a.from; i < a.to; i += 1) {
    if (tokens[i]!.t === "p" && tokens[i]!.v === "=>") {
      return "fn";
    }
  }
  if (first.t === "p" && first.v === "{") {
    return "object";
  }
  if (first.t === "id" && tokens.slice(a.from, a.to).every((t, k) => (k % 2 === 0 ? t.t === "id" : t.t === "p" && t.v === "."))) {
    return "ref";
  }
  return "other";
}

const literalOf = (tokens: Token[], a: Arg): string => tokens[a.from]!.v;
const refText = (tokens: Token[], a: Arg): string => tokens.slice(a.from, a.to).map((t) => t.v).join("");

function receiverChain(tokens: Token[], dot: number): string | null {
  const parts: string[] = [];
  let i = dot - 1;
  while (i >= 0 && tokens[i]!.t === "id") {
    parts.unshift(tokens[i]!.v);
    if (i - 1 >= 0 && tokens[i - 1]!.t === "p" && tokens[i - 1]!.v === "." && i - 2 >= 0 && tokens[i - 2]!.t === "id") {
      i -= 2;
    } else {
      break;
    }
  }
  return parts.length === 0 ? null : parts.join(".");
}

/** The value of `name: "literal"` inside an object-literal argument (top level of that object only), or `undefined` when the key is absent, `null` when it is not a literal. */
function objectProp(tokens: Token[], a: Arg, name: string): string | null | undefined {
  let depth = 0;
  for (let i = a.from; i < a.to; i += 1) {
    const t = tokens[i]!;
    if (t.t === "p" && (t.v === "{" || t.v === "[" || t.v === "(")) {
      depth += 1;
    } else if (t.t === "p" && (t.v === "}" || t.v === "]" || t.v === ")")) {
      depth -= 1;
    } else if (depth === 1 && (t.t === "id" || t.t === "str") && t.v === name && tokens[i + 1]?.t === "p" && tokens[i + 1]!.v === ":") {
      const v = tokens[i + 2];
      return v !== undefined && (v.t === "str" || (v.t === "tpl" && v.dyn !== true)) && (tokens[i + 3]?.v === "," || tokens[i + 3]?.v === "}" || tokens[i + 3] === undefined) ? v.v : null;
    }
  }
  return undefined;
}

const hasSpread = (tokens: Token[], a: Arg): boolean => tokens.slice(a.from, a.to).some((t) => t.t === "p" && t.v === "...");

const lastSegment = (receiver: string): string => receiver.split(".").pop()!;
const isMessaging = (receiver: string | null): boolean => receiver !== null && (MESSAGING_NAMES.has(lastSegment(receiver).toLowerCase()) || MESSAGING_SUFFIX.test(lastSegment(receiver)));

export function detectScript(source: string): EntityFact[] {
  const { tokens, truncated } = lexScript(source);
  const pairs = parenPairs(tokens);
  const out: EntityFact[] = [];
  let capped = false;
  const add = (fact: EntityFact): void => {
    if (out.length >= DETECTOR_LIMITS.entities) {
      capped = true;
      return;
    }
    out.push({ ...fact, key: cap(fact.key), name: cap(fact.name)!, target: cap(fact.target), handler: cap(fact.handler), receiver: cap(fact.receiver) });
  };
  const hasBaseUrl = tokens.some((t) => t.t === "id" && (t.v === "baseURL" || t.v === "baseUrl"));

  // variables created by a server framework factory in THIS file (`const router = express.Router()`): the only receivers, besides conventional names, that are treated as servers
  const serverVars = new Set<string>();
  for (let i = 0; i + 2 < tokens.length; i += 1) {
    if (tokens[i]!.t === "id" && tokens[i + 1]!.t === "p" && tokens[i + 1]!.v === "=" && !(tokens[i + 2]!.t === "p" && (tokens[i + 2]!.v === "=" || tokens[i + 2]!.v === ">"))) {
      for (let k = i + 2; k < i + 9 && k < tokens.length; k += 1) {
        if (tokens[k]!.t === "id" && SERVER_FACTORIES.has(tokens[k]!.v)) {
          serverVars.add(tokens[i]!.v);
          break;
        }
        if (tokens[k]!.t === "p" && tokens[k]!.v === ";") {
          break;
        }
      }
    }
  }
  const isServer = (receiver: string | null): boolean => {
    if (receiver === null) {
      return false;
    }
    const last = lastSegment(receiver);
    return serverVars.has(last) || SERVER_NAMES.test(last) || SERVER_SUFFIX.test(last);
  };

  let pendingController: string | null | undefined; // the @Controller prefix waiting for its class: undefined none, null unknown
  let classPrefix: string | null | undefined; // the prefix of the class being read (undefined: not a controller)

  for (let i = 0; i < tokens.length; i += 1) {
    const t = tokens[i]!;
    if (t.t === "id" && t.v === "class") {
      classPrefix = pendingController;
      pendingController = undefined;
      continue;
    }
    // ---- decorators (NestJS style) ----
    if (t.t === "p" && t.v === "@" && tokens[i + 1]?.t === "id" && tokens[i + 2]?.t === "p" && tokens[i + 2]!.v === "(") {
      const name = tokens[i + 1]!.v;
      const { args, close } = argsOf(tokens, pairs, i + 2);
      if (close === -1) {
        continue;
      }
      const firstKind = args[0] === undefined ? null : kindOf(tokens, args[0]);
      const lit = args.length === 0 ? "" : firstKind === "literal" ? literalOf(tokens, args[0]!) : firstKind === "object" ? (name === "Controller" ? objectProp(tokens, args[0]!, "path") ?? "" : null) ?? null : null;
      if (name === "Controller") {
        pendingController = lit; // a non-literal prefix (`@Controller(PREFIX)`) is unknown, not empty
      } else if (DECORATOR_METHODS[name.toLowerCase()] !== undefined && name[0] === name[0]!.toUpperCase() && classPrefix !== undefined) {
        let h = close + 1;
        while (h < tokens.length) {
          if (tokens[h]!.t === "p" && tokens[h]!.v === "@" && tokens[h + 1]?.t === "id") {
            h += 2;
            if (tokens[h]?.t === "p" && tokens[h]!.v === "(") {
              h = (pairs[h] ?? h) + 1; // skip another decorator's arguments
            }
            continue;
          }
          if (tokens[h]!.t === "id" && MODIFIERS.has(tokens[h]!.v)) {
            h += 1;
            continue;
          }
          break;
        }
        const handler = tokens[h]?.t === "id" && tokens[h + 1]?.t === "p" && tokens[h + 1]!.v === "(" ? tokens[h]!.v : null;
        const method = DECORATOR_METHODS[name.toLowerCase()]!;
        const path = lit === null || classPrefix === null ? null : joinPaths(classPrefix, lit);
        const unknown = path === null;
        add({ role: "server_route", kind: "route", key: path === null ? null : `${method} ${path}`, name: path === null ? `${method} <dynamic path>` : `${method} ${path}`, method, target: path, dynamic: unknown, receiver: null, handler, startLine: t.line, endLine: tokens[close]!.line, attrs: { style: "decorator" } });
      }
      continue;
    }
    if (t.t !== "id") {
      continue;
    }
    const next = tokens[i + 1];
    const prev = tokens[i - 1];
    const isMember = prev?.t === "p" && prev.v === "." && next?.t === "p" && next.v === "(";
    const isPlainCall = !(prev?.t === "p" && prev.v === ".") && next?.t === "p" && next.v === "(";
    const method = t.v.toLowerCase();

    // ---- member calls: routes, mounts, clients, events, jobs, prisma ----
    if (isMember) {
      const receiver = receiverChain(tokens, i - 1);
      const { args, close } = argsOf(tokens, pairs, i + 1);
      if (close === -1) {
        continue;
      }
      const kinds = args.map((a) => kindOf(tokens, a));
      const endLine = tokens[close]!.line;
      const first = args[0];
      const firstKind = kinds[0];
      const firstLiteral = first !== undefined && (firstKind === "literal" || firstKind === "template") ? literalOf(tokens, first) : null;
      const partialTemplate = firstKind === "template" && firstLiteral !== null && firstLiteral.startsWith("{}"); // an unknown leading part: the path is not known
      const laterHandler = args.length >= 2 && kinds.slice(1).some((k) => k === "fn" || k === "ref");

      if (HTTP_METHODS.has(method)) {
        const server = isServer(receiver);
        const pathLike = firstLiteral !== null && !partialTemplate && (firstLiteral.startsWith("/") || firstLiteral === "*");
        if (server && laterHandler) {
          const verb = method === "all" ? "ANY" : method.toUpperCase();
          const last = args[args.length - 1]!;
          const handler = kinds[kinds.length - 1] === "ref" ? refText(tokens, last) : null;
          if (pathLike) {
            const path = normalizePath(firstLiteral!);
            add({ role: "server_route", kind: "route", key: `${verb} ${path}`, name: `${verb} ${path}`, method: verb, target: path, dynamic: false, receiver, handler, startLine: tokens[i]!.line, endLine, attrs: { style: "call", inline: handler === null } });
          } else {
            add({ role: "server_route", kind: "route", key: null, name: `${verb} <dynamic path>`, method: verb, target: null, dynamic: true, receiver, handler, startLine: tokens[i]!.line, endLine, attrs: { style: "call", inline: handler === null, ...(partialTemplate ? { partialPath: firstLiteral!.slice(0, 120) } : {}) } });
          }
          continue;
        }
        const clientish = receiver !== null && CLIENT_RECEIVERS.test(lastSegment(receiver));
        const urlLike = firstLiteral !== null && !partialTemplate && (firstLiteral.startsWith("/") || /^https?:\/\//i.test(firstLiteral));
        if (first !== undefined && (clientish || urlLike) && !server && !kinds.includes("fn") && (clientish || !laterHandler) && (args.length === 1 || kinds[1] === "object" || kinds[1] === "other" || kinds[1] === "ref")) {
          addClient(add, tokens[i]!.line, endLine, method.toUpperCase(), partialTemplate ? null : firstLiteral, receiver, `${receiver ?? "?"}.${t.v}`, partialTemplate ? "partial_template" : null, clientish, hasBaseUrl);
          continue;
        }
      }
      if (method === "use" && isServer(receiver) && firstLiteral !== null && !partialTemplate && firstLiteral.startsWith("/") && args.length >= 2 && kinds[kinds.length - 1] === "ref") {
        add({ role: "mount", kind: "route", key: null, name: `mount ${firstLiteral}`, method: null, target: normalizePath(firstLiteral), dynamic: false, receiver, handler: refText(tokens, args[args.length - 1]!), startLine: tokens[i]!.line, endLine, attrs: null });
        continue;
      }
      const messaging = isMessaging(receiver);
      const isProducer = PRODUCER_METHODS.has(method) || ((method === "send" || method === "add") && messaging);
      const isConsumer = CONSUMER_METHODS.has(method) && ((method !== "on" && method !== "once" && method !== "addlistener") ? laterHandler || args.length === 1 : laterHandler);
      if ((isProducer || isConsumer) && first !== undefined && receiver !== null && !NOT_EVENT_SOURCES.has(lastSegment(receiver).toLowerCase())) {
        const objTopic = firstKind === "object" ? (objectProp(tokens, first, "topic") ?? objectProp(tokens, first, "queue") ?? null) : null;
        const name = firstKind === "literal" ? literalOf(tokens, first) : objTopic;
        // outside messaging-style receivers only namespaced, non-builtin literal names are plausible application events (`a.on("error")` is Node, not the app)
        const plausible = messaging || (name !== null && /[.:/]/.test(name) && !BUILTIN_EVENTS.has(name.toLowerCase()));
        if (plausible) {
          const lastRef = args.length >= 2 && kinds[kinds.length - 1] === "ref" ? refText(tokens, args[args.length - 1]!) : null;
          add({ role: isProducer ? "event_producer" : "event_consumer", kind: "event", key: name, name: name === null ? `<dynamic ${isProducer ? "producer" : "consumer"} name>` : name, method: t.v, target: name, dynamic: name === null, receiver, handler: isConsumer ? lastRef : null, startLine: tokens[i]!.line, endLine, attrs: { messagingReceiver: messaging } });
          continue;
        }
      }
      if (receiver !== null && /cron|scheduler|agenda|^schedule$/i.test(lastSegment(receiver)) && (method === "schedule" || method === "schedulejob" || method === "every" || method === "define") && firstLiteral !== null && !partialTemplate) {
        const last = args[args.length - 1]!;
        add({ role: "job", kind: "job", key: firstLiteral, name: `job ${firstLiteral}`, method: t.v, target: firstLiteral, dynamic: false, receiver, handler: kinds[kinds.length - 1] === "ref" ? refText(tokens, last) : null, startLine: tokens[i]!.line, endLine, attrs: null });
        continue;
      }
      if (receiver !== null && /^prisma\.[A-Za-z_$][\w$]*$/.test(receiver) && (PRISMA_READ.has(method) || PRISMA_WRITE.has(method))) {
        const model = receiver.split(".")[1]!;
        add({ role: "orm_access", kind: "db_query", key: `prisma ${model} ${method}`, name: `prisma.${model}.${t.v}`, method: t.v, target: model, dynamic: false, receiver, handler: null, startLine: tokens[i]!.line, endLine, attrs: { tables: [`${PRISMA_WRITE.has(method) ? "write" : "read"}:${model.toLowerCase()}`], mechanism: "orm_pattern" } });
        continue;
      }
    }

    // ---- plain calls: fetch(...), describe/it/test(...), new Worker / CronJob ----
    if (isPlainCall && t.v === "fetch") {
      const { args, close } = argsOf(tokens, pairs, i + 1);
      if (close !== -1 && args[0] !== undefined) {
        const k = kindOf(tokens, args[0]);
        const lit = k === "literal" || k === "template" ? literalOf(tokens, args[0]) : null;
        const partial = k === "template" && lit !== null && lit.startsWith("{}");
        // the method is KNOWN only when there is no options argument, or an options object literal without spread whose `method` is a literal or absent
        let verb: string | null = "GET";
        let note: string | null = null;
        if (args[1] !== undefined) {
          const optKind = kindOf(tokens, args[1]);
          if (optKind !== "object" || hasSpread(tokens, args[1])) {
            verb = null;
            note = "options_not_literal";
          } else {
            const m = objectProp(tokens, args[1], "method");
            if (m === null) {
              verb = null;
              note = "method_not_literal";
            } else if (m !== undefined) {
              verb = m.toUpperCase();
            }
          }
        }
        addClient(add, t.line, tokens[close]!.line, verb ?? "ANY", partial ? null : lit, "fetch", "fetch", partial ? "partial_template" : note, true, hasBaseUrl, verb === null);
      }
      continue;
    }
    if (isPlainCall && TEST_CALLS.has(t.v)) {
      const { args, close } = argsOf(tokens, pairs, i + 1);
      if (close !== -1 && args[0] !== undefined && kindOf(tokens, args[0]) === "literal" && args.length >= 2) {
        add({ role: "test_case", kind: "test", key: literalOf(tokens, args[0]), name: literalOf(tokens, args[0]), method: t.v, target: null, dynamic: false, receiver: null, handler: null, startLine: t.line, endLine: tokens[close]!.line, attrs: null });
      }
      continue;
    }
    if (prev?.t === "id" && prev.v === "new" && next?.t === "p" && next.v === "(" && (t.v === "Worker" || t.v === "CronJob")) {
      const { args, close } = argsOf(tokens, pairs, i + 1);
      if (close !== -1 && args[0] !== undefined) {
        const k = kindOf(tokens, args[0]);
        const lit = k === "literal" ? literalOf(tokens, args[0]) : null;
        const lastKind = args.length >= 2 ? kindOf(tokens, args[args.length - 1]!) : null;
        const handler = args.length >= 2 && lastKind === "ref" ? refText(tokens, args[args.length - 1]!) : null;
        if (t.v === "Worker") {
          if (lit !== null && (/^\.{0,2}\//.test(lit) || /\.(?:[cm]?[jt]s)$/.test(lit))) {
            continue; // `new Worker("./w.js")` is a worker thread, not a queue consumer
          }
          add({ role: "event_consumer", kind: "event", key: lit, name: lit ?? "<dynamic queue name>", method: "Worker", target: lit, dynamic: lit === null, receiver: "Worker", handler, startLine: t.line, endLine: tokens[close]!.line, attrs: { messagingReceiver: true } });
        } else {
          add({ role: "job", kind: "job", key: lit, name: lit === null ? "<dynamic schedule>" : `job ${lit}`, method: "CronJob", target: lit, dynamic: lit === null, receiver: "CronJob", handler, startLine: t.line, endLine: tokens[close]!.line, attrs: null });
        }
      }
      continue;
    }
    // ---- JSX routes: <Route path="/x" element={<Comp />} /> ----
    if (t.v === "Route" && prev?.t === "p" && prev.v === "<") {
      let path: string | null = null;
      let dynamicPath = false;
      let component: string | null = null;
      let k = i + 1;
      for (; k < tokens.length && k < i + 60; k += 1) {
        const a = tokens[k]!;
        if (a.t === "p" && (a.v === ">" || (a.v === "/" && tokens[k + 1]?.v === ">"))) {
          break;
        }
        if (a.t === "id" && tokens[k + 1]?.v === "=") {
          const v = tokens[k + 2];
          if (a.v === "path") {
            if (v?.t === "str") {
              path = v.v;
            } else {
              dynamicPath = true;
            }
          } else if ((a.v === "element" || a.v === "component" || a.v === "Component") && v?.t === "p" && v.v === "{") {
            const inner = tokens[k + 3];
            component = inner?.t === "p" && inner.v === "<" ? tokens[k + 4]?.v ?? null : inner?.t === "id" ? inner.v : null;
          } else if (a.v === "index") {
            path ??= "";
          }
        }
      }
      if (path !== null || dynamicPath) {
        const norm = path === null ? null : normalizePath(path === "" ? "/" : path);
        add({ role: "ui_route", kind: "ui_route", key: norm, name: norm === null ? "<dynamic ui path>" : `ui ${norm}`, method: null, target: norm, dynamic: path === null, receiver: null, handler: component, startLine: t.line, endLine: tokens[k]?.line ?? t.line, attrs: { style: "jsx" } });
      }
      continue;
    }
    // ---- route objects: { path: "/x", element: <Comp /> } ----
    if (t.v === "path" && tokens[i + 1]?.t === "p" && tokens[i + 1]!.v === ":" && tokens[i + 2]?.t === "str" && prev?.t === "p" && (prev.v === "{" || prev.v === ",")) {
      let component: string | null = null;
      let found = false;
      for (let k = i + 3; k < tokens.length && k < i + 40; k += 1) {
        const a = tokens[k]!;
        if (a.t === "p" && a.v === "}") {
          break;
        }
        if (a.t === "id" && (a.v === "element" || a.v === "component" || a.v === "Component") && tokens[k + 1]?.v === ":") {
          found = true;
          const v = tokens[k + 2];
          component = v?.t === "p" && v.v === "<" ? tokens[k + 3]?.v ?? null : v?.t === "id" ? v.v : null;
          break;
        }
      }
      if (found) {
        const norm = normalizePath(tokens[i + 2]!.v === "" ? "/" : tokens[i + 2]!.v);
        add({ role: "ui_route", kind: "ui_route", key: norm, name: `ui ${norm}`, method: null, target: norm, dynamic: false, receiver: null, handler: component, startLine: t.line, endLine: t.line, attrs: { style: "object" } });
      }
    }
  }
  detectSqlInStrings(tokens, add);
  // limits are reported, never silent: a coverage note becomes a gap in the builder
  if (truncated || capped) {
    out.push({ role: "coverage_note", kind: "coverage", key: null, name: "detection limit reached", method: null, target: null, dynamic: false, receiver: null, handler: null, startLine: 1, endLine: 1, attrs: { reason: truncated ? "token_limit" : "entity_limit" } });
  }
  return out;
}

function addClient(
  add: (f: EntityFact) => void, line: number, endLine: number, method: string, literal: string | null, receiver: string | null, call: string, note: string | null, knownClient: boolean,
  baseUrl = false, methodUnknown = false
): void {
  const flags = { call, knownClient, ...(note === null ? {} : { note }), ...(baseUrl ? { maybeBaseUrl: true } : {}), ...(methodUnknown ? { methodUnknown: true } : {}) };
  if (literal === null) {
    add({ role: "client_call", kind: "api_call", key: null, name: `${method} <dynamic url>`, method, target: null, dynamic: true, receiver, handler: null, startLine: line, endLine, attrs: flags });
    return;
  }
  const hostMatch = /^https?:\/\/([^/?#]*)(\/[^?#]*)?/i.exec(literal);
  const host = hostMatch === null ? null : (hostMatch[1] ?? "").split("@").pop()!.toLowerCase();
  const path = normalizePath(hostMatch === null ? literal : hostMatch[2] ?? "/");
  const external = host !== null && !/^(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/.test(host);
  // the literal is stored WITHOUT its query string or userinfo (they can carry tokens); only the host is kept
  add({ role: "client_call", kind: "api_call", key: `${method} ${path}`, name: `${method} ${path}`, method, target: path, dynamic: false, receiver, handler: null, startLine: line, endLine, attrs: { ...flags, ...(host === null ? {} : { host, external }) } });
}

const SQL_START = /^\s*(?:\/\*[\s\S]*?\*\/\s*|--[^\n]*\n\s*)*(select|insert|update|delete|replace|with)\b/i;
const NATURAL_WORDS = new Set(["is", "are", "was", "were", "be", "been", "to", "for", "of", "the", "a", "an", "it", "its", "not", "can", "will", "must", "should", "would", "could", "this", "that", "these", "those", "your", "you", "we", "they", "has", "have", "had", "do", "does", "did", "one", "all", "any", "each", "every", "please", "here", "there", "my", "our", "their", "his", "her"]);
const AFTER_TABLE_OK = new Set(["where", "join", "left", "right", "inner", "outer", "cross", "full", "natural", "on", "using", "group", "order", "limit", "offset", "union", "intersect", "except", "having", "returning", "values", "set", "select", "as", "default", "window", "fetch", "for", "lateral"]);
const TABLE = String.raw`["\`\[]?([A-Za-z_][\w$]*(?:\.[A-Za-z_][\w$]*)?)["\`\]]?`;
const NOISE_FUNCTIONS = /\b(?:extract|trim|substring|overlay|position|cast)\s*\([^()]*\)/gi;

/** Whether the text after a table name reads like SQL (a clause keyword, punctuation, an alias then a clause) rather than prose. */
function afterTableOk(text: string, end: number): boolean {
  const rest = text.slice(end, end + 80);
  const m = /^\s*([A-Za-z_]+|[;(),])?/.exec(rest);
  const word = (m?.[1] ?? "").toLowerCase();
  if (word === "" || /^[;(),]$/.test(word) || AFTER_TABLE_OK.has(word)) {
    return true;
  }
  // the word may be an alias (`from users u where`): it counts only if what follows it is a clause keyword, punctuation or the end
  const alias = /^\s*[A-Za-z_]+\s*([A-Za-z_]+|[;(),])?/.exec(rest);
  const following = (alias?.[1] ?? "").toLowerCase();
  return following === "" || /^[;(),]$/.test(following) || AFTER_TABLE_OK.has(following);
}

/** Tables a SQL text reads or writes, by statement keyword. Prose that merely starts with a SQL word is not SQL (see `afterTableOk` and the stop words). */
export function sqlTables(sql: string): Array<{ table: string; access: "read" | "write" }> {
  const text = sql.slice(0, DETECTOR_LIMITS.sqlLength).replace(NOISE_FUNCTIONS, " ");
  const found = new Map<string, "read" | "write">();
  const note = (table: string, access: "read" | "write", end: number, validate: boolean): void => {
    const name = table.toLowerCase();
    if (["select", "set", "values", "where", "from", "table", "into"].includes(name.split(".").pop()!) || NATURAL_WORDS.has(name.split(".").pop()!) || (validate && !afterTableOk(text, end))) {
      return;
    }
    found.set(name, found.get(name) === "write" || access === "write" ? "write" : "read");
  };
  for (const m of text.matchAll(new RegExp(String.raw`\binsert\s+into\s+${TABLE}`, "gi"))) { note(m[1]!, "write", (m.index ?? 0) + m[0].length, false); }
  for (const m of text.matchAll(new RegExp(String.raw`\breplace\s+into\s+${TABLE}`, "gi"))) { note(m[1]!, "write", (m.index ?? 0) + m[0].length, false); }
  for (const m of text.matchAll(new RegExp(String.raw`\bupdate\s+${TABLE}\s+set\b`, "gi"))) { note(m[1]!, "write", (m.index ?? 0) + m[0].length, false); }
  for (const m of text.matchAll(new RegExp(String.raw`\bdelete\s+from\s+${TABLE}`, "gi"))) { note(m[1]!, "write", (m.index ?? 0) + m[0].length, true); }
  if (/\bselect\b/i.test(text)) {
    for (const m of text.matchAll(new RegExp(String.raw`\b(?:from|join)\s+${TABLE}`, "gi"))) { note(m[1]!, "read", (m.index ?? 0) + m[0].length, true); }
  }
  return [...found].map(([table, access]) => ({ table, access })).sort((a, b) => (a.table < b.table ? -1 : 1));
}

function detectSqlInStrings(tokens: Token[], add: (f: EntityFact) => void): void {
  for (const t of tokens) {
    if ((t.t !== "str" && t.t !== "tpl") || t.v.length < 12 || !SQL_START.test(t.v)) {
      continue; // a SQL string STARTS with a statement keyword; prose that contains one elsewhere is not SQL
    }
    const tables = sqlTables(t.v);
    if (tables.length === 0) {
      continue;
    }
    const op = SQL_START.exec(t.v)![1]!.toLowerCase();
    add({
      role: "sql_query", kind: "db_query", key: `${op} ${tables.map((x) => x.table).join(",")}`, name: `${op} ${tables.map((x) => x.table).join(", ")}`, method: op, target: null,
      dynamic: false, receiver: null, handler: null, startLine: t.line, endLine: t.line, attrs: { tables: tables.map((x) => `${x.access}:${x.table}`), dynamicParts: t.dyn === true }
    });
  }
}

/** Line number of each offset in O(log n) (the entity count of a SQL file must not make this quadratic). */
function lineIndex(text: string): (offset: number) => number {
  const starts = [0];
  for (let i = 0; i < text.length; i += 1) {
    if (text.charCodeAt(i) === 10) {
      starts.push(i + 1);
    }
  }
  return (offset) => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid]! <= offset) {
        lo = mid;
      } else {
        hi = mid - 1;
      }
    }
    return lo + 1;
  };
}

/** `CREATE TABLE` statements (comments removed) and the DML a migration file contains. */
export function detectSql(source: string): EntityFact[] {
  const out: EntityFact[] = [];
  let capped = false;
  const stripped = source.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " ")).replace(/--[^\n]*/g, "");
  const lineOf = lineIndex(stripped);
  const push = (fact: EntityFact): void => {
    if (out.length >= DETECTOR_LIMITS.entities) {
      capped = true;
    } else {
      out.push({ ...fact, key: cap(fact.key), name: cap(fact.name)!, target: cap(fact.target) });
    }
  };
  for (const m of stripped.matchAll(new RegExp(String.raw`\bcreate\s+(?:temporary\s+|temp\s+)?table\s+(?:if\s+not\s+exists\s+)?${TABLE}`, "gi"))) {
    if (out.length >= DETECTOR_LIMITS.entities) {
      capped = true;
      break;
    }
    const name = m[1]!.toLowerCase(); // schema-qualified names stay qualified: `audit.users` and `public.users` are different tables
    const from = m.index ?? 0;
    const end = stripped.indexOf(";", from);
    const definition = stripped.slice(from, end === -1 ? Math.min(stripped.length, from + 20_000) : end).replace(/\s+/g, " ").toLowerCase();
    push({ role: "ddl_table", kind: "db_table", key: name, name, method: null, target: m[1]!, dynamic: false, receiver: null, handler: null, startLine: lineOf(from), endLine: lineOf(end === -1 ? from : end), attrs: { mechanism: "sql_ddl", defHash: createHash("sha256").update(definition).digest("hex").slice(0, 32) } });
  }
  let offset = 0;
  for (const statement of stripped.split(";")) {
    const at = offset;
    offset += statement.length + 1;
    if (!/^\s*(insert|update|delete|replace|select)\b/i.test(statement)) {
      continue;
    }
    if (out.length >= DETECTOR_LIMITS.entities) {
      capped = true;
      break;
    }
    const tables = sqlTables(statement);
    if (tables.length > 0) {
      const op = /^\s*(\w+)/.exec(statement)![1]!.toLowerCase();
      push({ role: "sql_query", kind: "db_query", key: `${op} ${tables.map((x) => x.table).join(",")}`, name: `${op} ${tables.map((x) => x.table).join(", ")}`, method: op, target: null, dynamic: false, receiver: null, handler: null, startLine: lineOf(at), endLine: lineOf(Math.min(offset, stripped.length)), attrs: { tables: tables.map((x) => `${x.access}:${x.table}`), dynamicParts: false } });
    }
  }
  if (capped) {
    out.push({ role: "coverage_note", kind: "coverage", key: null, name: "detection limit reached", method: null, target: null, dynamic: false, receiver: null, handler: null, startLine: 1, endLine: 1, attrs: { reason: "entity_limit" } });
  }
  return out;
}

const pathOfServerUrl = (url: unknown): string => {
  if (typeof url !== "string") {
    return "";
  }
  const m = /^https?:\/\/[^/]*(\/.*)?$/i.exec(url);
  return m === null ? (url.startsWith("/") ? url : "") : m[1] ?? "";
};

/** OpenAPI / Swagger JSON: one operation entity per documented path+method (the `basePath` or first `servers[].url` path is part of the identity). */
export function detectOpenApi(source: string): EntityFact[] {
  let doc: unknown;
  try {
    doc = JSON.parse(source);
  } catch {
    return [];
  }
  if (typeof doc !== "object" || doc === null || ((doc as Record<string, unknown>)["openapi"] === undefined && (doc as Record<string, unknown>)["swagger"] === undefined)) {
    return [];
  }
  const root = doc as Record<string, unknown>;
  const paths = root["paths"];
  if (typeof paths !== "object" || paths === null) {
    return [];
  }
  const servers = Array.isArray(root["servers"]) ? (root["servers"] as Array<{ url?: unknown }>) : [];
  const base = typeof root["basePath"] === "string" ? (root["basePath"] as string) : pathOfServerUrl(servers[0]?.url);
  const out: EntityFact[] = [];
  let capped = false;
  for (const [path, item] of Object.entries(paths as Record<string, unknown>)) {
    if (typeof item !== "object" || item === null) {
      continue;
    }
    for (const [verb, op] of Object.entries(item as Record<string, unknown>)) {
      if (!HTTP_METHODS.has(verb.toLowerCase())) {
        continue;
      }
      if (out.length >= DETECTOR_LIMITS.entities) {
        capped = true;
        break;
      }
      const method = verb.toUpperCase();
      const norm = joinPaths(base, path);
      const operationId = typeof (op as { operationId?: unknown })?.operationId === "string" ? (op as { operationId: string }).operationId.slice(0, 120) : null;
      out.push({ role: "spec_operation", kind: "api_operation", key: cap(`${method} ${norm}`), name: cap(`${method} ${norm}`)!, method, target: cap(path), dynamic: false, receiver: null, handler: null, startLine: 1, endLine: 1, attrs: { operationId, source: "openapi", ...(base === "" ? {} : { basePath: base.slice(0, 120) }) } });
    }
  }
  if (capped) {
    out.push({ role: "coverage_note", kind: "coverage", key: null, name: "detection limit reached", method: null, target: null, dynamic: false, receiver: null, handler: null, startLine: 1, endLine: 1, attrs: { reason: "entity_limit" } });
  }
  return out;
}

/** A `package.json` that depends on `next`: the marker that makes file-convention routing apply to that package. */
export function detectFrameworkMarkers(source: string): EntityFact[] {
  if (!source.includes("\"next\"") || source.length > 200_000) {
    return [];
  }
  try {
    const doc = JSON.parse(source) as Record<string, unknown>;
    const has = (k: string): boolean => typeof doc[k] === "object" && doc[k] !== null && Object.hasOwn(doc[k] as object, "next");
    return has("dependencies") || has("devDependencies") || has("peerDependencies")
      ? [{ role: "framework_marker", kind: "framework", key: "next", name: "next", method: null, target: null, dynamic: false, receiver: null, handler: null, startLine: 1, endLine: 1, attrs: null }]
      : [];
  } catch {
    return [];
  }
}
