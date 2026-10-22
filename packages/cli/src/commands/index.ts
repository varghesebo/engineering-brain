import { AuditLog, checkFreshness, indexRepository, Store, type FreshnessReport, type IndexResult } from "@engbrain/core";
import type { CliContext } from "../context.js";
import { EXIT, printable, printJsonOrText, type Io } from "../output.js";

function openStore(context: CliContext): Promise<Store> {
  return Store.open({ root: context.root, git: context.git, hardenedGit: context.hardenedGit, installId: context.installId });
}

const resolutionLine = (by: Record<string, number>): string =>
  ["resolved", "external", "unresolved", "ambiguous", "dynamic"].map((k) => `${k} ${by[k] ?? 0}`).join(", ");

function summaryText(result: IndexResult, detailed: boolean): string {
  const { stats, summary } = result;
  const reasons = Object.entries(stats.excludedByReason).map(([reason, count]) => `${printable(reason)}=${count}`).join(" ");
  const c = summary.changed;
  const lines = [
    `${result.unchanged ? "No changes; kept generation" : "Published generation"} ${result.generationId}`,
    `  files: ${stats.candidates} discovered, ${stats.included} indexed, ${stats.excluded} excluded${reasons === "" ? "" : ` (${reasons})`}, ${stats.missing} missing` +
      (c === null ? "" : `; since previous: +${c.added} ~${c.modified} -${c.deleted} renamed ${c.renamed}`),
    `  parsing: ${stats.parser.parsed} parsed (${stats.parser.failed} with errors), ${stats.parser.skipped} unsupported, facts reused for ${stats.factsReused} files`,
    `  code: ${summary.symbols} symbols (${summary.exportedSymbols} exported), ${summary.edges.total} module relationships (${resolutionLine(summary.edges.byResolution)})`,
    `  fingerprint: ${result.sourceFingerprint}`,
    `  took ${stats.durationMs} ms`
  ];
  if (detailed) {
    lines.push(
      `  languages: ${Object.entries(summary.byLanguage).map(([k, v]) => `${k} ${v}`).join(", ") || "none"}`,
      `  parser coverage (published): ok ${summary.parser.ok}, errors ${summary.parser.error}, unsupported ${summary.parser.skipped}; diagnostics ${summary.diagnostics}`,
      `  this run: ${stats.parser.symbolsExtracted} symbols and ${stats.parser.refsExtracted} references extracted`,
      `  database: ${(stats.dbSizeBytes / 1048576).toFixed(2)} MiB   peak memory: ${stats.peakRssMiB} MiB (process peak, measured)`
    );
  }
  return lines.join("\n");
}

export async function indexCommand(io: Io, context: CliContext, json: boolean, flags: { stats: boolean }): Promise<void> {
  const store = await openStore(context);
  try {
    const config = store.config();
    const audit = new AuditLog(store.dir, context.installId, { maxFileBytes: config.auditMaxFileBytes, maxFiles: config.auditMaxFiles, retentionDays: config.auditRetentionDays });
    const result = await indexRepository({ store, git: context.git, hardenedGit: context.hardenedGit, audit });
    if (store.historyChanged) {
      io.stderr("note: repository history changed since init (root commits rewritten, or a different repository is at this path)\n");
    }
    printJsonOrText(
      io, json,
      { generationId: result.generationId, unchanged: result.unchanged, revision: result.revision, sourceFingerprint: result.sourceFingerprint, stats: result.stats, summary: result.summary },
      summaryText(result, flags.stats)
    );
  } finally {
    store.close();
  }
}

export function freshnessText(report: FreshnessReport): string {
  const list = (label: string, items: string[]): string[] => (items.length === 0 ? [] : [`  ${label}: ${items.map(printable).join(", ")}${report.truncated ? " …" : ""}`]);
  return [
    `freshness: ${report.level}  (${report.basis})`,
    ...(report.revisionChanged ? [`  revision changed: indexed ${report.indexedRevision ?? "(none)"}, now ${report.currentRevision ?? "(none)"}`] : []),
    ...(report.indexerChanged ? ["  this build would extract or resolve differently than the one that built the index: run `engbrain index`"] : []),
    ...list("added", report.added), ...list("modified", report.modified), ...list("deleted", report.deleted)
  ].join("\n");
}

/** `index --check`: verify, by content hash, that the published index matches the working tree. Writes nothing. */
export async function indexCheckCommand(io: Io, context: CliContext, json: boolean): Promise<number> {
  const store = await openStore(context);
  try {
    const report = await checkFreshness(store, context.git, context.hardenedGit, { verify: true });
    printJsonOrText(io, json, { ...report }, freshnessText(report));
    return report.level === "hash_verified" ? EXIT.ok : EXIT.error;
  } finally {
    store.close();
  }
}
