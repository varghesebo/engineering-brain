import { createHash } from "node:crypto";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { resolve } from "node:path";
import {
  acceptEvidence, addVerifier, analyzeImpact, authenticate, checkFreshness, closeHandoff, createHandoff, EngbrainError, EVIDENCE_FORMATS, EVIDENCE_MAX_BYTES, importEvidence, listEvidence, listHandoffs, rejectEvidence, selectTests, showEvidence, showHandoff,
  Store, verificationStatus, type EvidenceFormat
} from "@engbrain/core";
import type { CliContext } from "../context.js";
import { EXIT, printable, printJsonOrText, type Io } from "../output.js";

export interface EvidenceCommandOptions {
  positionals: string[];
  format: string | undefined;
  revision: string | undefined;
  tree: string | undefined;
  runCommand: string | undefined;
  env: string[];
  verifier: string | undefined;
  signature: string | undefined;
  since: string | undefined;
  sample: number | undefined;
  file: string | undefined;
  task: string | undefined;
  scope: string[];
  refs: string[];
  hypotheses: string[];
  blockers: string[];
  pending: string[];
  ttlHours: number | undefined;
  limit: number | undefined;
}

export type EvidenceGroup = "impact" | "tests" | "evidence" | "handoff";

function readArtifact(io: Io, path: string): Buffer {
  const full = resolve(io.cwd, path);
  const stat = lstatSync(full);
  if (!stat.isFile() || stat.size > EVIDENCE_MAX_BYTES) {
    throw new EngbrainError("POLICY_REFUSED", "the artifact must be a regular file of at most 20 MiB");
  }
  return readFileSync(full);
}

function parseEnv(pairs: string[]): Record<string, string> {
  const env: Record<string, string> = {};
  for (const pair of pairs) {
    const cut = pair.indexOf("=");
    if (cut < 1) {
      throw new EngbrainError("POLICY_REFUSED", "--env takes key=value");
    }
    env[pair.slice(0, cut)] = pair.slice(cut + 1);
  }
  return env;
}

/** Stable id of this working tree: two worktrees of one repository have different roots, so their handoffs are told apart. */
export const worktreeIdOf = (root: string): string => createHash("sha256").update(realpathSync(root)).digest("hex").slice(0, 12);

const usage = (io: Io, message: string): number => {
  io.stderr(`error: ${message}\n`);
  return EXIT.usage;
};

export async function evidenceCommand(io: Io, context: CliContext, json: boolean, group: EvidenceGroup, o: EvidenceCommandOptions): Promise<number> {
  const open = { root: context.root, git: context.git, hardenedGit: context.hardenedGit, installId: context.installId };
  const sub = o.positionals[0];
  const writes = (group === "evidence" && ["import", "accept", "reject", "verifier"].includes(sub ?? "")) || (group === "handoff" && ["create", "close"].includes(sub ?? ""));
  const store = writes ? await Store.open(open) : await Store.openReadOnly(open);
  try {
    const db = store.db;
    if (!writes) {
      // answers describe the last PUBLISHED generation: say so when files or HEAD have moved since (a handoff or an evidence standing is judged against the index, not the disk)
      const fresh = await checkFreshness(store, context.git, context.hardenedGit, { verify: false });
      if (fresh.level === "stale" || fresh.level === "unknown") {
        io.stderr(`warning: the index is ${fresh.level}: results describe the last published generation, not the current files (run \`engbrain refresh\`)\n`);
      }
    }
    if (group === "impact" || group === "tests") {
      if (group === "tests" && sub !== "select") {
        return usage(io, "tests needs: select <files...> [--since <commit>] [--sample <n>]");
      }
      const files = group === "tests" ? o.positionals.slice(1) : o.positionals;
      if (files.length === 0 && o.since === undefined) {
        return usage(io, `${group === "tests" ? "tests select" : "impact"} needs changed files or --since <commit>`);
      }
      const base = { files, ...(o.since === undefined ? {} : { since: o.since }) };
      if (group === "impact") {
        const r = analyzeImpact(db, base);
        const lines = [
          ...r.impacted.map((i) => `${i.class.padEnd(18)} d${i.distance}  ${printable(i.path)}  (${printable(i.via)}; because of ${i.because.map(printable).join(", ")})`),
          ...r.unknownInputs.map((u) => `UNKNOWN  ${printable(u.path)}: ${printable(u.reason)}`),
          `missed-edge risk: ${r.missedEdgeRisk.level}${r.missedEdgeRisk.reasons.map((x) => `\n  - ${printable(x)}`).join("")}`, r.disclaimer
        ];
        printJsonOrText(io, json, { result: r }, lines.join("\n"));
        return EXIT.ok;
      }
      const s = selectTests(db, { ...base, ...(o.sample === undefined ? {} : { sample: o.sample }) });
      const lines = [
        ...s.selected.map((t) => `${t.proof.padEnd(22)} ${t.certainty.padEnd(9)} ${printable(t.path)}  (for ${t.for.map(printable).join(", ")})`),
        ...s.unmapped.map((p) => `NO TEST MAPPED (unknown, not safe): ${printable(p)}`), ...s.sample.map((t) => `sample  ${printable(t.path)}`),
        `${s.selected.length} of ${s.totalTests} tests selected; missed-edge risk ${s.analysis.missedEdgeRisk.level}`, s.advisory
      ];
      printJsonOrText(io, json, { result: s }, lines.join("\n"));
      return EXIT.ok;
    }
    if (group === "handoff") {
      switch (sub) {
        case "create": {
          if (o.task === undefined || o.scope.length === 0) {
            return usage(io, "handoff create needs --task <text> and at least one --scope <path>");
          }
          const actor = authenticate(store.dir, io.env);
          const h = createHandoff(db, store.dir, {
            task: o.task, scope: o.scope, references: o.refs, hypotheses: o.hypotheses, blockers: o.blockers, pendingEvidence: o.pending, worktreeId: worktreeIdOf(context.root),
            ...(o.ttlHours === undefined ? {} : { ttlHours: o.ttlHours })
          }, { actor });
          printJsonOrText(io, json, { id: h.handoff_id, expiresAt: h.expires_at, fingerprint: h.source_fingerprint }, `handoff ${h.handoff_id} written (expires ${h.expires_at}); it goes stale when a file in scope or the policy changes`);
          return EXIT.ok;
        }
        case "show": {
          if (o.positionals[1] === undefined) {
            return usage(io, "handoff show needs an id");
          }
          const v = showHandoff(db, store.dir, o.positionals[1], { worktreeId: worktreeIdOf(context.root) });
          if (v === null) {
            io.stderr("error: no such handoff\n");
            return EXIT.error;
          }
          const lines = [
            `${v.id}  ${v.standing}${v.usable ? "" : "  (NOT usable)"}  by ${printable(v.author)} at ${v.createdAt}`, `task: ${printable(v.task)}`, `scope: ${v.scope.map(printable).join(", ")}`,
            ...v.hypotheses.map((h) => `hypothesis (unverified): ${printable(h.text)}`), ...v.blockers.map((b) => `blocker: ${printable(b)}`), ...v.pendingEvidence.map((p) => `pending evidence: ${printable(p)}`),
            ...v.reasons.map((r) => `note: ${printable(r)}`), ...v.conflicts.map((c) => `CONFLICT with ${c.id} (${printable(c.author)}): ${c.overlap.map(printable).join(", ")}`), v.notice
          ];
          printJsonOrText(io, json, { handoff: v }, lines.join("\n"));
          return v.usable ? EXIT.ok : EXIT.error;
        }
        case "list": {
          const items = listHandoffs(db, store.dir, o.limit === undefined ? {} : { limit: o.limit });
          printJsonOrText(io, json, { handoffs: items }, items.map((h) => `${h.id}  ${h.standing.padEnd(10)} ${printable(h.author)}  ${printable(h.task)}`).join("\n") || "no handoffs");
          return EXIT.ok;
        }
        case "close": {
          if (o.positionals[1] === undefined) {
            return usage(io, "handoff close needs an id");
          }
          closeHandoff(db, o.positionals[1], { actor: authenticate(store.dir, io.env) });
          io.stdout(`handoff ${printable(o.positionals[1])} closed\n`);
          return EXIT.ok;
        }
        default:
          return usage(io, "handoff needs: create | show <id> | list | close <id>");
      }
    }
    switch (sub) {
      case "import": {
        const path = o.positionals[1];
        if (path === undefined || o.format === undefined || !(EVIDENCE_FORMATS as readonly string[]).includes(o.format)) {
          return usage(io, `evidence import needs <artifact file> --format ${EVIDENCE_FORMATS.join("|")} [--revision <commit> --run-command <cmd> --env k=v --verifier <id> --signature <hex>]`);
        }
        const row = importEvidence(db, store.dir, {
          format: o.format as EvidenceFormat, repoRoot: context.root, data: readArtifact(io, path), artifactName: path.split("/").pop() ?? path, ...(o.revision === undefined ? {} : { revision: o.revision }), ...(o.tree === undefined ? {} : { tree: o.tree }),
          ...(o.runCommand === undefined ? {} : { command: o.runCommand }), environment: parseEnv(o.env), ...(o.verifier === undefined ? {} : { verifier: o.verifier }), ...(o.signature === undefined ? {} : { signature: o.signature })
        }, { actor: authenticate(store.dir, io.env) });
        const reasons = JSON.parse(row.provenance_json) as string[];
        printJsonOrText(io, json, { id: row.import_id, trust: row.trust, signature: row.signature_status, counts: { total: row.total, passed: row.passed, failed: row.failed, skipped: row.skipped }, reasons },
          `imported ${row.import_id} as ${row.trust.toUpperCase()} (${row.passed} passed, ${row.failed} failed, ${row.skipped} skipped of ${row.total})${row.trust === "quarantined" ? `\nit counts for nothing until a signature verifies or an operator accepts it:\n${reasons.map((r) => `  - ${printable(r)}`).join("\n")}` : ""}`);
        return EXIT.ok;
      }
      case "list": {
        const items = listEvidence(db, o.limit === undefined ? {} : { limit: o.limit });
        printJsonOrText(io, json, { imports: items }, items.map((i) => `${i.id}  ${i.format.padEnd(9)} ${i.trust.padEnd(11)} ${i.standing.padEnd(12)} ${i.counts.passed}/${i.counts.total} passed  ${printable(i.artifactName)}`).join("\n") || "no evidence imported");
        return EXIT.ok;
      }
      case "show": {
        const d = o.positionals[1] === undefined ? null : showEvidence(db, o.positionals[1]);
        if (d === null) {
          io.stderr("error: no such evidence import\n");
          return EXIT.error;
        }
        const lines = [
          `${d.id}  ${d.format}  trust ${d.trust}  standing ${d.standing}  signature ${d.signature}`, `artifact ${printable(d.artifactName)} sha256 ${d.artifactSha256.slice(0, 16)}...  revision ${d.sourceRevision?.slice(0, 10) ?? "-"}  verifier ${printable(d.verifier ?? "-")}`,
          ...d.reasons.map((r) => `  - ${printable(r)}`), ...d.results.map((r) => `  ${r.outcome.padEnd(9)} ${printable(r.name)}${r.file === null ? "" : `  (${printable(r.file)})`}`), ...(d.resultsTruncated ? ["  ... results truncated"] : [])
        ];
        printJsonOrText(io, json, { evidence: d }, lines.join("\n"));
        return EXIT.ok;
      }
      case "accept":
      case "reject": {
        if (o.positionals[1] === undefined) {
          return usage(io, `evidence ${sub} needs an import id`);
        }
        const actor = authenticate(store.dir, io.env);
        const row = (sub === "accept" ? acceptEvidence : rejectEvidence)(db, o.positionals[1], { actor });
        io.stdout(`${row.import_id} is now ${row.trust}\n`);
        return EXIT.ok;
      }
      case "verifier": {
        if (o.positionals[1] !== "add" || o.positionals[2] === undefined) {
          return usage(io, "evidence verifier add <id>");
        }
        const v = addVerifier(store.dir, { id: o.positionals[2], actor: authenticate(store.dir, io.env) });
        printJsonOrText(io, json, { verifier: v.id, key: v.keyHex }, `verifier ${v.id} registered.\nsigning key (store it in your CI secret store; sign with HMAC-SHA256 over the artifact bytes): ${v.keyHex}`);
        return EXIT.ok;
      }
      case "status": {
        const s = verificationStatus(db, o.file === undefined ? {} : { file: o.file });
        printJsonOrText(io, json, { status: s }, [...s.usable.map((u) => `${u.outcome.padEnd(9)} ${u.standing.padEnd(10)} ${printable(u.test)}${u.file === null ? "" : `  (${printable(u.file)})`}`), `${s.imports} imports; ${s.quarantined} quarantined or rejected (counted for nothing)`].join("\n"));
        return EXIT.ok;
      }
      default:
        return usage(io, "evidence needs: import | list | show <id> | accept <id> | reject <id> | verifier add <id> | status");
    }
  } finally {
    store.close();
  }
}
