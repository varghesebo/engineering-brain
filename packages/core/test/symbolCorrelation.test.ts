import { describe, expect, it } from "vitest";
import { correlateSymbols, type CorrelatedSymbol } from "../src/symbolCorrelation.js";

const s = (path: string, qualifiedName: string, extra: Partial<CorrelatedSymbol> = {}): CorrelatedSymbol => ({
  path, kind: "function", qualifiedName, signatureFingerprint: "sig-" + qualifiedName, symbolKey: `k-${qualifiedName}`, contentHash: `h-${path}`, ...extra
});

describe("cross-version symbol correlation", () => {
  it("identical content is the only non-inferred match, even when the file moved", () => {
    const r = correlateSymbols([s("a.ts", "f", { contentHash: "H" })], [s("moved/a.ts", "f", { contentHash: "H" })]);
    expect(r.matches).toEqual([expect.objectContaining({ basis: "identical_content", inferred: false, confidence: "certain" })]);
    expect(r.added).toEqual([]);
    expect(r.removed).toEqual([]);
  });

  it("a changed file keeps its symbol by path+name, but the match is INFERRED", () => {
    const r = correlateSymbols([s("a.ts", "f", { contentHash: "old" })], [s("a.ts", "f", { contentHash: "new" })]);
    expect(r.matches).toEqual([expect.objectContaining({ basis: "same_path_same_name", inferred: true, confidence: "high" })]);
  });

  it("a symbol moved to another file is a medium-confidence inference only when unique", () => {
    const r = correlateSymbols([s("a.ts", "f", { contentHash: "1" })], [s("b.ts", "f", { contentHash: "2" })]);
    expect(r.matches).toEqual([expect.objectContaining({ basis: "same_name_moved", inferred: true, confidence: "medium" })]);
  });

  it("a rename with an identical signature is a LOW-confidence inference, never asserted as exact", () => {
    const r = correlateSymbols(
      [s("a.ts", "oldName", { signatureFingerprint: "SIG", contentHash: "1" })],
      [s("a.ts", "newName", { signatureFingerprint: "SIG", contentHash: "2" })]
    );
    expect(r.matches).toEqual([expect.objectContaining({ basis: "same_signature_renamed", inferred: true, confidence: "low" })]);
    expect(r.matches.every((m) => m.inferred)).toBe(true);
  });

  it("ambiguous cases produce no match: two removed and two added with the same signature", () => {
    const r = correlateSymbols(
      [s("a.ts", "x", { signatureFingerprint: "SIG", contentHash: "1" }), s("a.ts", "y", { signatureFingerprint: "SIG", contentHash: "1" })],
      [s("a.ts", "p", { signatureFingerprint: "SIG", contentHash: "2" }), s("a.ts", "q", { signatureFingerprint: "SIG", contentHash: "2" })]
    );
    expect(r.matches).toEqual([]);
    expect(r.ambiguous.length).toBe(2);
    expect(r.ambiguous[0]?.basis).toBe("same_signature_renamed");
    expect(r.added).toEqual([]); // the ambiguous candidates are reserved, never ALSO reported as added
    expect(r.removed).toEqual([]); // ...and the ambiguous originals are never ALSO reported as removed
  });

  it("the same name in two other files is ambiguous, not guessed", () => {
    const r = correlateSymbols([s("a.ts", "f", { contentHash: "1" })], [s("b.ts", "f", { contentHash: "2" }), s("c.ts", "f", { contentHash: "3" })]);
    expect(r.matches).toEqual([]);
    expect(r.ambiguous).toEqual([expect.objectContaining({ basis: "same_name_moved" })]);
  });

  it("unmatched symbols are reported as added or removed, nothing is invented", () => {
    const r = correlateSymbols([s("a.ts", "gone", { signatureFingerprint: null, contentHash: "1" })], [s("a.ts", "fresh", { signatureFingerprint: null, contentHash: "2" })]);
    expect(r.matches).toEqual([]);
    expect(r.removed.map((x) => x.qualifiedName)).toEqual(["gone"]);
    expect(r.added.map((x) => x.qualifiedName)).toEqual(["fresh"]);
  });

  it("is deterministic regardless of input order", () => {
    const before = [s("a.ts", "a", { contentHash: "1" }), s("b.ts", "b", { contentHash: "1" }), s("c.ts", "c", { contentHash: "1" })];
    const after = [s("a.ts", "a", { contentHash: "2" }), s("c.ts", "renamed", { signatureFingerprint: "sig-c", contentHash: "2" })];
    expect(correlateSymbols(before, after)).toEqual(correlateSymbols([...before].reverse(), [...after].reverse()));
  });
});

describe("correlation consistency (review fixes)", () => {
  it("a symbol is never both matched and ambiguous", () => {
    const before = [s("a.ts", "helper", { signatureFingerprint: "S", contentHash: "1" }), s("c.ts", "helper", { signatureFingerprint: "S", contentHash: "1" })];
    const after = [s("b.ts", "helper", { signatureFingerprint: "S", contentHash: "2" }), s("d.ts", "helper", { signatureFingerprint: "S", contentHash: "2" })];
    const r = correlateSymbols(before, after);
    const matched = new Set(r.matches.map((m) => m.before));
    expect(r.ambiguous.every((x) => !matched.has(x.before))).toBe(true);
    expect(r.matches).toEqual([]);
  });
  it("identical bytes copied to two NEW paths is ambiguous, not a certain match to the first path", () => {
    const r = correlateSymbols([s("a.ts", "f", { contentHash: "H" })], [s("b.ts", "f", { contentHash: "H" }), s("c.ts", "f", { contentHash: "H" })]);
    expect(r.matches).toEqual([]);
    expect(r.ambiguous).toEqual([expect.objectContaining({ basis: "identical_content" })]);
    expect(r.added).toEqual([]);
  });
  it("a file that stays put keeps its certain match even when an identical copy appears elsewhere", () => {
    const r = correlateSymbols([s("a.ts", "f", { contentHash: "H" })], [s("a.ts", "f", { contentHash: "H" }), s("copy.ts", "f", { contentHash: "H" })]);
    expect(r.matches).toEqual([expect.objectContaining({ basis: "identical_content", inferred: false })]);
    expect(r.added.map((x) => x.path)).toEqual(["copy.ts"]);
  });
  it("scales: 20,000 symbols correlate in well under a second", () => {
    const many = (n: number, tag: string): CorrelatedSymbol[] => Array.from({ length: n }, (_, i) => s(`f${i % 500}.ts`, `sym${i}`, { contentHash: tag, symbolKey: `k${i}`, signatureFingerprint: null }));
    const started = performance.now();
    correlateSymbols(many(20_000, "old"), many(20_000, "new"));
    expect(performance.now() - started).toBeLessThan(1000);
  });
});
