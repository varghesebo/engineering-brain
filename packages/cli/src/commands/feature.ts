import { lstatSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  approveClaim, EngbrainError, rebindClaim, featureImpact, featureProvenance, listClaims, listFeatures, listGaps, loadAnnotations, resolveAnnotations, retireClaim, showFeature, Store, submitCandidates, traceFrom,
  validateFeatureGraph, type ClaimRecord
} from "@engbrain/core";
import type { CliContext } from "../context.js";
import { EXIT, printable, printJsonOrText, type Io } from "../output.js";
import { toRepoPath } from "../paths.js";

export const FEATURE_ACTIONS = new Set(["list", "show", "trace", "impact", "provenance", "gaps", "claims", "propose", "approve", "rebind", "retire", "validate"]);
export type FeatureAction = "list" | "show" | "trace" | "impact" | "provenance" | "gaps" | "claims" | "propose" | "approve" | "rebind" | "retire" | "validate";

export interface FeatureOptions {
  arg: string | undefined;
  search: string | undefined;
  file: string | undefined;
  symbol: string | undefined;
  depth: number | undefined;
  limit: number | undefined;
  direction: string | undefined;
  by: string | undefined;
  reason: string | undefined;
  fromFile: string | undefined;
  source: string | undefined;
  sourceDetail: string | undefined;
  kind: string | undefined;
  yes: boolean;
}

const READ_ONLY_ACTIONS = new Set<FeatureAction>(["list", "show", "trace", "impact", "provenance", "gaps", "claims", "validate"]);

function claimLine(c: ClaimRecord): string {
  return `#${c.id}  ${c.trust.toUpperCase()}  [${printable(c.label)}]  evidence ${c.evidenceStatus}  ${printable(c.statement)}`;
}

export async function featureCommand(io: Io, context: CliContext, json: boolean, action: FeatureAction, o: FeatureOptions): Promise<number> {
  const readOnly = READ_ONLY_ACTIONS.has(action);
  const open = { root: context.root, git: context.git, hardenedGit: context.hardenedGit, installId: context.installId };
  const store = readOnly ? await Store.openReadOnly(open) : await Store.open(open);
  try {
    const db = store.db;
    switch (action) {
      case "list": {
        const generated = listFeatures(db, { ...(o.limit === undefined ? {} : { limit: o.limit }), ...(o.search === undefined ? {} : { search: o.search }), ...(o.kind === undefined ? {} : { rootKind: o.kind }) });
        const annotations = loadAnnotations(context.root);
        const annotated = resolveAnnotations(db, annotations.features);
        const lines = [
          ...generated.features.map((f) => `${printable(f.id)}  [${f.trust}, ${f.confidence}]  ${f.members} members  ${f.services.length} services${f.gaps > 0 ? `  ${f.gaps} gaps` : ""}${f.truncated ? "  (truncated)" : ""}`),
          ...annotated.map((a) => `${printable(a.id)}  [annotation: human-authored]  ${a.members.length} documented members, ${a.notFound} not found in code`),
          ...annotations.problems.map((p) => `annotation problem in ${printable(p.file)}: ${printable(p.problem)}`),
          generated.generationId === null ? "no index yet: run `engbrain index`" : `${generated.total} discovered features (candidate groupings from generation ${generated.generationId})${generated.truncated ? "; more exist (use --limit)" : ""}`
        ];
        printJsonOrText(io, json, { generated, annotations: { files: annotations.files, problems: annotations.problems, features: annotated } }, lines.join("\n"));
        return EXIT.ok;
      }
      case "show": {
        const id = needArg(o.arg, "show needs a feature id");
        const found = showFeature(db, id, o.limit === undefined ? {} : { limit: o.limit });
        if (!found.found) {
          const annotated = resolveAnnotations(db, loadAnnotations(context.root).features.filter((a) => a.id === id))[0];
          if (annotated !== undefined) {
            const lines = [
              `${printable(annotated.name)}  [annotation: human-authored, not generated]`,
              ...annotated.members.map((m) => `  ${m.status.padEnd(24)} ${printable(JSON.stringify(m.selector))}${m.entities.length === 0 ? "" : `  -> ${m.entities.map((e) => printable(e.name)).join(", ")}`}`),
              ...annotated.constraints.map((c) => `  documented constraint (NOT verified): ${printable(c.statement)}  [source: ${printable(c.source)}]`)
            ];
            printJsonOrText(io, json, { annotation: annotated }, lines.join("\n"));
            return EXIT.ok;
          }
          io.stderr(`error: ${found.note}\n`);
          return EXIT.error;
        }
        const lines = [
          `${printable(found.feature!.name)}  [${found.feature!.trust}]`, found.note,
          ...found.members.map((m) => `  ${"  ".repeat(Math.min(m.hops, 4))}${m.kind.padEnd(11)} ${printable(m.name)}${m.path === null ? "" : `  ${printable(m.path)}${m.startLine === null ? "" : `:${m.startLine}`}`}  [${m.certainty ?? "-"}]`),
          ...found.gaps.map((g) => `  GAP ${g.kind}: ${printable(g.detail)}`), ...(found.truncated ? ["  (members truncated: use --limit)"] : [])
        ];
        printJsonOrText(io, json, { feature: found }, lines.join("\n"));
        return EXIT.ok;
      }
      case "trace": {
        const ref = needArg(o.arg, "trace needs an entity (an id, kind:key such as `route:GET /api/users`, file:path or sym:path#name)");
        const direction = o.direction === undefined ? "both" : o.direction;
        if (direction !== "forward" && direction !== "reverse" && direction !== "both") {
          io.stderr("error: --direction must be forward, reverse or both\n");
          return EXIT.usage;
        }
        const t = traceFrom(db, ref, { direction, ...(o.depth === undefined ? {} : { depth: o.depth }) });
        if (t.start === null) {
          io.stderr(`error: ${t.note}\n`);
          return EXIT.error;
        }
        const name = new Map(t.nodes.map((n) => [n.id, `${n.kind} ${n.name}`]));
        const lines = [
          `${printable(`${t.start.kind} ${t.start.name}`)}`,
          ...t.edges.map((e) => `  ${printable(name.get(e.src) ?? e.src)} --${e.relation} [${e.certainty}: ${e.reason}]--> ${printable(name.get(e.dst) ?? e.dst)}`),
          ...t.gaps.map((g) => `  GAP ${g.kind}: ${printable(g.detail)}`),
          `${t.nodes.length} nodes, ${t.edges.length} edges${Object.entries(t.truncated).filter(([, v]) => v).map(([k]) => `; truncated by ${k}`).join("")}`, t.note,
          ...(t.alsoMatched.length > 0 ? [`also matched: ${t.alsoMatched.map(printable).join(", ")}`] : [])
        ];
        printJsonOrText(io, json, { trace: t }, lines.join("\n"));
        return EXIT.ok;
      }
      case "impact": {
        if (o.file === undefined && o.symbol === undefined) {
          io.stderr("error: impact needs --file <path> or --symbol <path#name>\n");
          return EXIT.usage;
        }
        const r = featureImpact(db, o.symbol !== undefined ? { symbol: `${toRepoPath(context.root, io.cwd, o.symbol.slice(0, o.symbol.lastIndexOf("#")))}#${o.symbol.slice(o.symbol.lastIndexOf("#") + 1)}` } : { file: toRepoPath(context.root, io.cwd, o.file!) }, o.depth === undefined ? {} : { depth: o.depth });
        if (!r.found) {
          io.stderr("error: that file or symbol is not in the published index\n");
          return EXIT.error;
        }
        const lines = [
          `${r.entities.length} feature entities located here; ${r.features.length} features touched; ${r.reached.length} connected nodes${r.truncated ? " (truncated)" : ""}`,
          ...r.entities.map((e) => `  ${e.kind.padEnd(11)} ${printable(e.name)}`), ...r.features.map((f) => `  feature ${printable(f.id)}`), r.disclaimer
        ];
        printJsonOrText(io, json, { impact: r }, lines.join("\n"));
        return EXIT.ok;
      }
      case "provenance": {
        const id = needArg(o.arg, "provenance needs a feature id");
        const p = featureProvenance(db, id, o.limit === undefined ? {} : { limit: o.limit });
        if (!p.found) {
          io.stderr(`error: ${p.note}\n`);
          return EXIT.error;
        }
        const lines = [
          `${printable(p.feature!.name)}  generation ${p.generationId}  revision ${p.revision?.slice(0, 10) ?? "-"}  source ${p.sourceFingerprint?.slice(0, 12) ?? "-"}`,
          ...p.members.map((m) => `  ${m.kind.padEnd(11)} ${printable(m.name)}  ${m.mechanism ?? "-"}  ${m.certainty ?? "-"}  ${m.path === null ? "" : `${printable(m.path)}:${m.line ?? 0}`}  hash ${m.contentHash?.slice(0, 10) ?? "-"}  since generation ${m.validFromGeneration ?? "-"}`),
          ...p.lineage.map((l) => `  lineage ${l.kind} (${l.certainty}): ${l.basis}`), p.note
        ];
        printJsonOrText(io, json, { provenance: p }, lines.join("\n"));
        return EXIT.ok;
      }
      case "gaps": {
        const g = listGaps(db, { ...(o.kind === undefined ? {} : { kind: o.kind }), ...(o.limit === undefined ? {} : { limit: o.limit }) });
        printJsonOrText(io, json, { gaps: g }, [...g.gaps.map((x) => `${x.kind}  ${x.path === null ? "" : `${printable(x.path)}:${x.line ?? 0}  `}${printable(x.detail)}`), `${g.total} coverage gaps${g.truncated ? " (truncated)" : ""}`].join("\n"));
        return EXIT.ok;
      }
      case "validate": {
        const v = validateFeatureGraph(db);
        printJsonOrText(io, json, { validation: v }, v.ok ? "feature graph is consistent" : v.problems.join("\n"));
        return v.ok ? EXIT.ok : EXIT.error;
      }
      case "claims": {
        const claims = listClaims(db, o.kind === "candidate" || o.kind === "approved" || o.kind === "retired" ? { trust: o.kind } : {});
        printJsonOrText(io, json, { claims }, claims.length === 0 ? "no claims" : claims.map(claimLine).join("\n"));
        return EXIT.ok;
      }
      case "propose": {
        if (o.fromFile === undefined) {
          io.stderr("error: propose needs --from-file <proposals.json> (a JSON array of { statement, evidence })\n");
          return EXIT.usage;
        }
        const source = o.source === undefined ? "human" : o.source;
        if (source !== "model" && source !== "human") {
          io.stderr("error: --source must be model or human\n");
          return EXIT.usage;
        }
        const path = resolve(io.cwd, o.fromFile);
        const stat = lstatSync(path);
        if (!stat.isFile() || stat.size > 1_048_576) {
          throw new EngbrainError("POLICY_REFUSED", "the proposals file must be a regular file of at most 1 MiB");
        }
        const doc = JSON.parse(readFileSync(path, "utf8")) as unknown;
        const list = Array.isArray(doc) ? doc : typeof doc === "object" && doc !== null && Array.isArray((doc as { proposals?: unknown }).proposals) ? (doc as { proposals: unknown[] }).proposals : null;
        if (list === null) {
          throw new EngbrainError("POLICY_REFUSED", "expected a JSON array of proposals");
        }
        const result = submitCandidates(db, list, { source, ...(o.sourceDetail === undefined ? {} : { sourceDetail: o.sourceDetail }) });
        printJsonOrText(io, json, { result }, `${result.inserted} recorded as candidates (inferred/proposed, NOT verified), ${result.duplicates} duplicates ignored, ${result.rejected.length} rejected${result.rejected.map((r) => `\n  #${r.index}: ${printable(r.reason)}`).join("")}`);
        return EXIT.ok;
      }
      case "approve": {
        const id = Number(needArg(o.arg, "approve needs a claim number"));
        if (!o.yes || o.by === undefined) {
          io.stderr("error: approval is a human decision: pass --by <your name> and --yes\n");
          return EXIT.usage;
        }
        const claim = approveClaim(db, id, { approvedBy: o.by });
        printJsonOrText(io, json, { claim }, claimLine(claim));
        return EXIT.ok;
      }
      case "rebind": {
        const id = Number(needArg(o.arg, "rebind needs a claim number"));
        const claim = rebindClaim(db, id);
        printJsonOrText(io, json, { claim }, claimLine(claim));
        return EXIT.ok;
      }
      case "retire": {
        const id = Number(needArg(o.arg, "retire needs a claim number"));
        if (o.reason === undefined) {
          io.stderr("error: retire needs --reason <text>\n");
          return EXIT.usage;
        }
        const claim = retireClaim(db, id, { reason: o.reason });
        printJsonOrText(io, json, { claim }, claimLine(claim));
        return EXIT.ok;
      }
    }
  } finally {
    store.close();
  }
}

function needArg(value: string | undefined, message: string): string {
  if (value === undefined || value === "") {
    throw new EngbrainError("INVALID_ROOT", message);
  }
  return value;
}
