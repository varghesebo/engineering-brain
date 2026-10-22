import { assembleContext, checkFreshness, EngbrainError, Store } from "@engbrain/core";
import type { CliContext } from "../context.js";
import { printable, printJsonOrText, type Io } from "../output.js";
import { summarizeFreshness } from "../mcp/tools.js";

export async function contextCommand(io: Io, context: CliContext, json: boolean, task: string, maxTokens: number | undefined): Promise<void> {
  const store = await Store.openReadOnly({ root: context.root, git: context.git, hardenedGit: context.hardenedGit, installId: context.installId });
  try {
    const freshness = await checkFreshness(store, context.git, context.hardenedGit, { verify: false });
    const packet = assembleContext(store.db, { task, root: context.root, header: { freshness: summarizeFreshness(freshness) }, ...(maxTokens === undefined ? {} : { maxTokens }) });
    if (packet === null) {
      throw new EngbrainError("NOT_INITIALIZED", "no index yet: run `engbrain index`");
    }
    const lines: string[] = [`task context  generation ${packet.snapshot.generationId}  freshness ${freshness.level}  ~${packet.budget.estimatedTokens}/${packet.budget.maxTokens} tokens${packet.budget.truncated ? "  (truncated)" : ""}`, ""];
    for (const f of packet.files) {
      lines.push(`${printable(f.path)}  score ${f.score}  [${printable(f.why.join("; "))}]`);
      for (const s of f.symbols) {
        lines.push(`  ${s.startLine ?? "?"}  ${s.kind ?? ""} ${printable(s.qualifiedName ?? s.name)}`);
      }
      if (f.excerpt?.available === true) {
        lines.push(...f.excerpt.text!.split("\n").map((l) => `    | ${printable(l)}`));
      }
    }
    for (const r of packet.related) {
      lines.push(`${r.role}: ${printable(r.path)}  (of ${printable(r.of)}, ${r.via.kind} ${r.via.resolution})`);
    }
    for (const t of packet.tests) {
      lines.push(`test: ${printable(t.path)}  (${t.basis}, for ${printable(t.forPath)})`);
    }
    lines.push("", ...packet.uncertainty.map((u) => `note: ${u}`));
    if (packet.nextCursor !== null) {
      lines.push("more results exist (use --json to read nextCursor)");
    }
    printJsonOrText(io, json, { packet }, lines.join("\n"));
  } finally {
    store.close();
  }
}
