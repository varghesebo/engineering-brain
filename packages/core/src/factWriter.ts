import type Database from "better-sqlite3";
import { extractorApplies, type ExtractedFact, type Extractor } from "./extractor.js";

export interface FactWriterOptions {
  batchSize?: number;
  /** Called after each committed batch with its 1-based index (fault-injection point for tests). */
  onBatchFlushed?: (batchIndex: number) => void;
}

/**
 * Writes content-addressed facts (and their symbols/references) for a set of extractors. Facts are immutable and
 * keyed by (content hash, extractor id, extractor version); nothing references them until a generation publishes
 * or a ledger row points at them. Used by the working-tree indexer and by commit-blob ingestion alike.
 */
export class FactWriter {
  private readonly hasFactStmt: Database.Statement;
  private readonly insertFactStmt: Database.Statement;
  private readonly insertSymbolStmt: Database.Statement;
  private readonly insertRefStmt: Database.Statement;
  private readonly insertExportStmt: Database.Statement;
  private readonly insertRelationStmt: Database.Statement;
  private readonly insertSymbolRefStmt: Database.Statement;
  private readonly insertDiagnosticStmt: Database.Statement;
  private readonly insertEntityStmt: Database.Statement;
  private readonly pending: Array<{ hash: string; extractor: Extractor; fact: ExtractedFact }> = [];
  private readonly queued = new Set<string>();
  private readonly batchSize: number;
  private batches = 0;
  /** Per-extractor counters for this writer's lifetime (observable run statistics). */
  readonly counts = new Map<string, { ok: number; error: number; skipped: number; symbols: number; refs: number }>();

  constructor(
    private readonly db: Database.Database,
    readonly extractors: readonly Extractor[],
    private readonly options: FactWriterOptions = {}
  ) {
    this.batchSize = options.batchSize ?? 500;
    this.hasFactStmt = db.prepare("SELECT 1 FROM file_facts WHERE content_hash = ? AND extractor_id = ? AND extractor_version = ?");
    this.insertFactStmt = db.prepare(
      "INSERT OR IGNORE INTO file_facts (content_hash, extractor_id, extractor_version, language, parse_status, attrs_json) VALUES (?, ?, ?, ?, ?, ?)"
    );
    this.insertSymbolStmt = db.prepare(
      `INSERT OR IGNORE INTO symbols (content_hash, extractor_id, extractor_version, local_id, kind, name, qualified_name, parent_local_id, symbol_key,
         start_line, start_col, end_line, end_col, start_byte, end_byte, signature_fingerprint, exported, export_name, anonymous, parameters_json)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );
    this.insertRefStmt = db.prepare(
      `INSERT OR IGNORE INTO syntax_refs (content_hash, extractor_id, extractor_version, local_id, ref_kind, target_text, names_json, line)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    );
    this.insertExportStmt = db.prepare(
      `INSERT OR IGNORE INTO exports (content_hash, extractor_id, extractor_version, local_id, export_kind, export_name, local_name, symbol_local_id, source_text, line)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );
    this.insertRelationStmt = db.prepare(
      `INSERT OR IGNORE INTO symbol_relations (content_hash, extractor_id, extractor_version, local_id, symbol_local_id, relation, target_text, line)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    );
    this.insertSymbolRefStmt = db.prepare(
      `INSERT OR IGNORE INTO symbol_refs (content_hash, extractor_id, extractor_version, local_id, symbol_local_id, name, line)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    );
    this.insertEntityStmt = db.prepare(
      `INSERT OR IGNORE INTO fact_entities (content_hash, extractor_id, extractor_version, local_id, role, kind, key, name, method, target, dynamic, receiver, handler, start_line, end_line, attrs_json)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );
    this.insertDiagnosticStmt = db.prepare(
      `INSERT OR IGNORE INTO fact_diagnostics (content_hash, extractor_id, extractor_version, local_id, severity, code, message, line, col)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );
  }

  async prepare(): Promise<void> {
    await Promise.all(this.extractors.map((extractor) => extractor.prepare?.()));
  }

  private key(hash: string, extractor: Extractor): string {
    return `${hash}\0${extractor.id}@${extractor.version}`;
  }

  /** True when every extractor that applies to `path` already has facts for `hash` (so the bytes need not be read again). */
  hasAllFacts(hash: string, path: string): boolean {
    return this.extractors.every((e) => !extractorApplies(e, path) || this.queued.has(this.key(hash, e)) || this.hasFactStmt.get(hash, e.id, e.version) !== undefined);
  }

  /** Runs every extractor that lacks facts for `hash`. Returns true when at least one extractor actually ran. */
  add(hash: string, path: string, data: Buffer): boolean {
    let ran = false;
    for (const extractor of this.extractors) {
      if (!extractorApplies(extractor, path)) {
        continue; // this extractor produces nothing for this path: no fact, not even a placeholder
      }
      const key = this.key(hash, extractor);
      if (this.queued.has(key) || this.hasFactStmt.get(hash, extractor.id, extractor.version) !== undefined) {
        continue;
      }
      const fact = this.extractSafely(extractor, path, data);
      const tally = this.counts.get(extractor.id) ?? { ok: 0, error: 0, skipped: 0, symbols: 0, refs: 0 };
      tally[fact.parseStatus] += 1;
      tally.symbols += Math.max(0, (fact.symbols?.length ?? 0) - 1);
      tally.refs += fact.refs?.length ?? 0;
      this.counts.set(extractor.id, tally);
      this.pending.push({ hash, extractor, fact });
      this.queued.add(key);
      ran = true;
    }
    if (this.pending.length >= this.batchSize) {
      this.flush();
    }
    return ran;
  }

  /** An extractor failure must never abort an index run: the file gets an `error` fact with a generic diagnostic. */
  private extractSafely(extractor: Extractor, path: string, data: Buffer): ExtractedFact {
    try {
      return extractor.extract({ path, data });
    } catch {
      return {
        language: null, parseStatus: "error", attrs: { reason: "extractor_exception" },
        diagnostics: [{ severity: "error", code: "extractor_exception", message: "extractor failed on this file", line: 1, column: 0 }]
      };
    }
  }

  flush(): void {
    if (this.pending.length === 0) {
      return;
    }
    this.db.transaction(() => {
      for (const { hash, extractor, fact } of this.pending) {
        const inserted = this.insertFactStmt.run(hash, extractor.id, extractor.version, fact.language, fact.parseStatus, JSON.stringify(fact.attrs));
        if (inserted.changes === 0) {
          continue;
        }
        (fact.symbols ?? []).forEach((sym, index) =>
          this.insertSymbolStmt.run(
            hash, extractor.id, extractor.version, index, sym.kind, sym.name, sym.qualifiedName, sym.parentIndex, sym.symbolKey,
            sym.startLine, sym.startColumn, sym.endLine, sym.endColumn, sym.startByte, sym.endByte, sym.signatureFingerprint,
            sym.exported ? 1 : 0, sym.exportName, sym.anonymous ? 1 : 0, sym.parameters === null ? null : JSON.stringify(sym.parameters)
          )
        );
        (fact.refs ?? []).forEach((ref, index) =>
          this.insertRefStmt.run(hash, extractor.id, extractor.version, index, ref.kind, ref.target, ref.names === null ? null : JSON.stringify(ref.names), ref.line)
        );
        (fact.exports ?? []).forEach((exp, index) =>
          this.insertExportStmt.run(hash, extractor.id, extractor.version, index, exp.kind, exp.exportName, exp.localName, exp.symbolIndex, exp.source, exp.line)
        );
        (fact.relations ?? []).forEach((rel, index) =>
          this.insertRelationStmt.run(hash, extractor.id, extractor.version, index, rel.symbolIndex, rel.relation, rel.target, rel.line)
        );
        (fact.symbolRefs ?? []).forEach((ref, index) =>
          this.insertSymbolRefStmt.run(hash, extractor.id, extractor.version, index, ref.symbolIndex, ref.name, ref.line)
        );
        (fact.entities ?? []).forEach((e, index) =>
          this.insertEntityStmt.run(hash, extractor.id, extractor.version, index, e.role, e.kind, e.key, e.name, e.method, e.target, e.dynamic ? 1 : 0, e.receiver, e.handler, e.startLine, e.endLine, e.attrs === null ? null : JSON.stringify(e.attrs))
        );
        (fact.diagnostics ?? []).forEach((diag, index) =>
          this.insertDiagnosticStmt.run(hash, extractor.id, extractor.version, index, diag.severity, diag.code, diag.message, diag.line, diag.column)
        );
      }
    }).immediate();
    this.pending.length = 0;
    this.queued.clear();
    this.batches += 1;
    this.options.onBatchFlushed?.(this.batches);
  }
}
