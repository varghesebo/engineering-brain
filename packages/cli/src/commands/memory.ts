import { lstatSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  addMemory, addOperator, approveMemory, authenticate, checkFreshness, collectMemory, EngbrainError, revokeOperator, rotateOperator, evaluateRecord, evidenceProvenance, exportMemory, listStale, loadOperators, MEMORY_KINDS, parseNewMemory,
  ciEvidenceSupports, recordInvalidations, rejectMemory, relatedBugs, relatedDecisions, searchMemory, setDistinctApprover, setEnvironment, showMemory, Store, summarizeMemory, verifyMemory,
  type MemoryItem, type MemoryKind, type MemoryRow, type OperatorRole
} from "@engbrain/core";
import type { CliContext } from "../context.js";
import { EXIT, printable, printJsonOrText, type Io } from "../output.js";

export type MemoryGroup = "memory" | "bugs" | "decisions" | "evidence";
export const MEMORY_ACTIONS = new Set(["operator", "add", "approve", "verify", "reject", "env", "search", "show", "stale", "summary", "gc", "export"]);

export interface MemoryOptions {
  positionals: string[];
  roles: string | undefined;
  fromFile: string | undefined;
  reason: string | undefined;
  kind: string | undefined;
  includeCandidates: boolean;
  includeStale: boolean;
  asOfValid: string | undefined;
  asOfRecorded: string | undefined;
  limit: number | undefined;
  maxTokens: number | undefined;
  file: string | undefined;
  symbol: string | undefined;
  feature: string | undefined;
  out: string | undefined;
  record: boolean;
  yes: boolean;
  failOnStale: boolean;
}

const WRITE_ACTIONS = new Set(["add", "approve", "verify", "reject"]);
const READ_ACTIONS = new Set(["search", "show", "stale", "summary", "provenance", "related"]);

function itemLine(i: MemoryItem): string {
  return `${i.id}  ${i.kind.padEnd(14)} [${i.status}${i.authoritative ? ", authoritative" : ""}]  ${printable(i.title)}${i.evidencePaths.length === 0 ? "" : `  (${i.evidencePaths.map(printable).join(", ")})`}`;
}

function readJsonFile(io: Io, path: string): unknown {
  const full = resolve(io.cwd, path);
  const stat = lstatSync(full);
  if (!stat.isFile() || stat.size > 262_144) {
    throw new EngbrainError("POLICY_REFUSED", "the file must be a regular file of at most 256 KiB");
  }
  return JSON.parse(readFileSync(full, "utf8")) as unknown;
}

export async function memoryCommand(io: Io, context: CliContext, json: boolean, group: MemoryGroup, o: MemoryOptions): Promise<number> {
  const sub = o.positionals[0];
  const open = { root: context.root, git: context.git, hardenedGit: context.hardenedGit, installId: context.installId };
  const mutating = group === "memory" && sub !== undefined && (WRITE_ACTIONS.has(sub) || sub === "env" && o.positionals[1] === "set" || sub === "operator" || (sub === "stale" && o.record) || sub === "gc");
  const store = mutating ? await Store.open(open) : await Store.openReadOnly(open);
  try {
    const db = store.db;
    const now = (): Date => new Date();
    // memory is judged against the last PUBLISHED generation: if the working tree or HEAD moved since, say so (and optionally refuse), instead of answering as if it were current
    let indexFreshness: string | null = null;
    if (!mutating && (READ_ACTIONS.has(sub ?? "") || group !== "memory")) {
      const fresh = await checkFreshness(store, context.git, context.hardenedGit, { verify: false });
      indexFreshness = fresh.level;
      if (fresh.level === "stale" || fresh.level === "unknown") {
        if (o.failOnStale) {
          io.stderr(`error: the index is ${fresh.level}: run \`engbrain refresh\` (fail-on-stale is on)\n`);
          return EXIT.refused;
        }
        io.stderr(`warning: the index is ${fresh.level} (the working tree or HEAD changed since the last refresh): memory is judged against the last published generation, not the current files\n`);
      }
    }
    const evaluate = (row: MemoryRow) => evaluateRecord(db, row, now().toISOString());
    if (group === "bugs" || group === "decisions") {
      if (sub !== "related") {
        io.stderr(`error: ${group} needs: related --file <path> | --symbol <path#name> | --feature <entity>\n`);
        return EXIT.usage;
      }
      if (o.file === undefined && o.symbol === undefined && o.feature === undefined) {
        io.stderr("error: name what to look up with --file, --symbol or --feature\n");
        return EXIT.usage;
      }
      const target = { ...(o.file === undefined ? {} : { file: o.file }), ...(o.symbol === undefined ? {} : { symbol: o.symbol }), ...(o.feature === undefined ? {} : { feature: o.feature }) };
      const result = (group === "bugs" ? relatedBugs : relatedDecisions)(db, target, { includeStale: o.includeStale, ...(o.limit === undefined ? {} : { limit: o.limit }) });
      const lines = result.items.flatMap((i) => [
        itemLine(i), `    ${printable(i.label)}`,
        ...i.fixes.map((f) => `    fix ${f.id} [${f.status}]  ${printable(f.title)}`), ...i.verifications.map((v) => `    verification ${v.id} [${v.status}${v.reasons.length > 0 ? `: ${printable(v.reasons[0]!)}` : ""}]  ${printable(v.title)}`)
      ]);
      lines.push(`${result.items.length} shown; excluded: ${Object.entries(result.excluded).filter(([, n]) => n > 0).map(([k, n]) => `${n} ${k}`).join(", ") || "none"}`, result.note);
      printJsonOrText(io, json, { result, indexFreshness }, lines.join("\n"));
      return EXIT.ok;
    }
    if (group === "evidence") {
      if (sub !== "provenance" || o.positionals[1] === undefined) {
        io.stderr("error: evidence needs: provenance <memory id>\n");
        return EXIT.usage;
      }
      const p = evidenceProvenance(db, o.positionals[1]);
      if (!p.found) {
        io.stderr("error: no such memory record\n");
        return EXIT.error;
      }
      const lines = [
        `${itemLine(p.item!)}`, `  ${printable(p.item!.label)}`, `  evidence ${p.evidenceType}${p.method === null ? "" : ` via ${printable(p.method)}`}  proposer ${printable(p.proposer ?? "-")}  approver ${printable(p.approver ?? "-")}  verified by ${printable(p.verifiedBy ?? "-")}`,
        ...p.pointers.map((x) => `  pointer ${x.kind.padEnd(11)} ${printable(x.path ?? x.ref ?? "")}  ${x.state}`), ...p.predicates.map((x) => `  predicate ${printable(JSON.stringify(x.predicate))}  ${x.result}${x.reason === null ? "" : ` (${printable(x.reason)})`}`),
        ...p.commits.map((c) => `  commit ${c.oid.slice(0, 10)}  ${c.role}`), ...p.events.map((e) => `  event ${e.at}  ${e.kind}  by ${printable(e.actor)}`)
      ];
      printJsonOrText(io, json, { provenance: p, indexFreshness }, lines.join("\n"));
      return EXIT.ok;
    }
    switch (sub) {
      case "operator": {
        const action = o.positionals[1];
        if (action === "add") {
          const id = o.positionals[2];
          const roles = (o.roles ?? "propose").split(",").map((r) => r.trim()).filter((r) => r !== "") as OperatorRole[];
          if (id === undefined) {
            io.stderr("error: operator add needs an id and --roles propose,approve,verify,admin\n");
            return EXIT.usage;
          }
          const existing = loadOperators(store.dir).operators.length;
          const actor = existing === 0 ? null : authenticate(store.dir, io.env);
          const created = addOperator(store.dir, { id, roles, actor, confirmBootstrap: o.yes });
          printJsonOrText(io, json, { operator: created.id, token: created.token }, `operator ${created.id} created.\ntoken (shown once, store it safely): ${created.token}\nuse it as ENGBRAIN_OPERATOR=${created.id} ENGBRAIN_OPERATOR_TOKEN=<token>`);
          return EXIT.ok;
        }
        if (action === "revoke" && o.positionals[2] !== undefined) {
          revokeOperator(store.dir, { id: o.positionals[2], actor: authenticate(store.dir, io.env) });
          io.stdout(`operator ${printable(o.positionals[2])} revoked\n`);
          return EXIT.ok;
        }
        if (action === "rotate" && o.positionals[2] !== undefined) {
          const rotated = rotateOperator(store.dir, { id: o.positionals[2], actor: authenticate(store.dir, io.env) });
          printJsonOrText(io, json, { operator: rotated.id, token: rotated.token }, `new token for ${rotated.id} (shown once; the old one no longer works): ${rotated.token}`);
          return EXIT.ok;
        }
        if (action === "distinct" && (o.positionals[2] === "on" || o.positionals[2] === "off")) {
          setDistinctApprover(store.dir, authenticate(store.dir, io.env), o.positionals[2] === "on");
          io.stdout(`distinct approver: ${o.positionals[2]}\n`);
          return EXIT.ok;
        }
        io.stderr("error: operator needs: add <id> --roles ... [--yes for the first] | revoke <id> | rotate <id> | distinct on|off\n");
        return EXIT.usage;
      }
      case "add": {
        if (o.fromFile === undefined) {
          io.stderr("error: add needs --from-file <record.json>\n");
          return EXIT.usage;
        }
        const actor = authenticate(store.dir, io.env);
        const record = addMemory(db, parseNewMemory(readJsonFile(io, o.fromFile)), { actor, now });
        printJsonOrText(io, json, { id: record.record_id, status: record.status }, `recorded ${record.record_id} as ${record.status} (never authoritative until approved by an authorised operator)`);
        return EXIT.ok;
      }
      case "approve":
      case "verify": {
        const id = o.positionals[1];
        if (id === undefined) {
          io.stderr(`error: ${sub} needs a memory id\n`);
          return EXIT.usage;
        }
        const actor = authenticate(store.dir, io.env);
        const row = (sub === "approve" ? approveMemory : verifyMemory)(db, id, { actor, now, evaluate, distinctApprover: loadOperators(store.dir).distinctApprover, ciSupports: (r) => ciEvidenceSupports(db, r.evidence_json, now().toISOString()) });
        printJsonOrText(io, json, { id: row.record_id, status: row.status }, `${row.record_id} is now ${row.status}`);
        return EXIT.ok;
      }
      case "reject": {
        const id = o.positionals[1];
        if (id === undefined || o.reason === undefined) {
          io.stderr("error: reject needs a memory id and --reason <text>\n");
          return EXIT.usage;
        }
        const row = rejectMemory(db, id, { actor: authenticate(store.dir, io.env), reason: o.reason, now });
        printJsonOrText(io, json, { id: row.record_id, status: row.status }, `${row.record_id} rejected`);
        return EXIT.ok;
      }
      case "env": {
        if (o.positionals[1] === "set" && o.positionals[2] !== undefined && o.positionals[3] !== undefined) {
          setEnvironment(db, o.positionals[2], o.positionals.slice(3).join(" "), { actor: authenticate(store.dir, io.env), now });
          io.stdout(`environment ${printable(o.positionals[2])} recorded\n`);
          return EXIT.ok;
        }
        if (o.positionals[1] === "list") {
          const rows = db.prepare("SELECT key, value, recorded_at AS at FROM memory_environment WHERE id IN (SELECT MAX(id) FROM memory_environment GROUP BY key) ORDER BY key").all() as Array<{ key: string; value: string; at: string }>;
          printJsonOrText(io, json, { environment: rows }, rows.map((r) => `${printable(r.key)} = ${printable(r.value)}  (${r.at})`).join("\n") || "no environment facts recorded");
          return EXIT.ok;
        }
        io.stderr("error: env needs: set <key> <value> | list\n");
        return EXIT.usage;
      }
      case "search": {
        const kinds = o.kind === undefined ? undefined : [o.kind as MemoryKind];
        if (kinds !== undefined && !MEMORY_KINDS.includes(kinds[0]!)) {
          io.stderr(`error: --kind must be one of ${MEMORY_KINDS.join(", ")}\n`);
          return EXIT.usage;
        }
        const result = searchMemory(db, {
          query: o.positionals.slice(1).join(" "), includeCandidates: o.includeCandidates, includeStale: o.includeStale, now,
          ...(kinds === undefined ? {} : { kinds }), ...(o.asOfValid === undefined ? {} : { asOfValid: o.asOfValid }), ...(o.asOfRecorded === undefined ? {} : { asOfRecorded: o.asOfRecorded }),
          ...(o.limit === undefined ? {} : { limit: o.limit }), ...(o.maxTokens === undefined ? {} : { maxTokens: o.maxTokens })
        });
        const lines = [...result.items.flatMap((i) => [itemLine(i), `    ${printable(i.label)}${i.reasons.length > 0 ? `  [${printable(i.reasons[0]!)}]` : ""}`]),
          `${result.items.length} shown${result.truncated ? " (truncated)" : ""}; excluded: ${Object.entries(result.excluded).filter(([, n]) => n > 0).map(([k, n]) => `${n} ${k}`).join(", ") || "none"}`, result.note];
        printJsonOrText(io, json, { result, indexFreshness }, lines.join("\n"));
        return EXIT.ok;
      }
      case "show": {
        const id = o.positionals[1];
        const d = id === undefined ? null : showMemory(db, id);
        if (d === null) {
          io.stderr("error: no such memory record\n");
          return EXIT.error;
        }
        printJsonOrText(io, json, { memory: d, indexFreshness }, [itemLine(d), `  ${printable(d.label)}`, `  recorded ${d.recordedAt}  valid from ${d.validFrom}${d.validTo === null ? "" : ` to ${d.validTo}`}`, ...d.body.split("\n").map((l) => `  | ${printable(l)}`)].join("\n"));
        return EXIT.ok;
      }
      case "stale": {
        if (o.record) {
          const n = recordInvalidations(db, { actor: authenticate(store.dir, io.env), now, evaluate });
          io.stdout(`${n} invalidation events recorded (stored statuses are not changed: standing is computed on every read)\n`);
          return EXIT.ok;
        }
        const report = listStale(db, { now });
        const lines = [...report.stale.map((i) => `STALE   ${itemLine(i)}\n        ${printable(i.reasons.join("; ") || "marked stale")}`), ...report.unknown.map((i) => `UNKNOWN ${itemLine(i)}\n        ${printable(i.reasons.join("; "))}`), ...report.outOfScope.map((i) => `OTHER BRANCH ${itemLine(i)}`)];
        printJsonOrText(io, json, { report, indexFreshness }, lines.join("\n") || "no stale or unknown records");
        return EXIT.ok;
      }
      case "summary": {
        const s = summarizeMemory(db, { now, ...(o.maxTokens === undefined ? {} : { maxTokens: o.maxTokens }) });
        printJsonOrText(io, json, { summary: s, indexFreshness }, [...s.lines.map(printable), `${s.omitted} more omitted (see \`memory search\`); ~${s.estimatedTokens} tokens; excluded: ${Object.entries(s.excluded).filter(([, n]) => n > 0).map(([k, n]) => `${n} ${k}`).join(", ") || "none"}`].join("\n"));
        return EXIT.ok;
      }
      case "gc": {
        const r = collectMemory(db, { actor: authenticate(store.dir, io.env), now });
        io.stdout(`${r.removed} expired observations removed\n`);
        return EXIT.ok;
      }
      case "export": {
        const data = exportMemory(db);
        if (o.out !== undefined) {
          writeFileSync(resolve(io.cwd, o.out), `${JSON.stringify(data, null, 2)}\n`, { flag: "wx", mode: 0o600 });
          io.stdout(`exported ${data.records.length} records to ${printable(o.out)} (${data.withheld} withheld: they look like secrets)\n`);
        } else {
          io.stdout(`${JSON.stringify(data, null, 2)}\n`);
        }
        return EXIT.ok;
      }
      default:
        io.stderr(`error: memory needs one of: ${[...MEMORY_ACTIONS].join(", ")}\n`);
        return EXIT.usage;
    }
  } finally {
    store.close();
  }
}
