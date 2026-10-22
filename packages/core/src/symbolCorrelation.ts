import type { SymbolKind } from "./extractor.js";

/**
 * Correlating symbols across two versions of a codebase. A source location is never a permanent identity: refactors
 * move and rename things. Only `identical_content` (same file bytes, same symbol key) is proof of sameness; every other
 * match is an INFERENCE and is marked `inferred: true` with a basis and confidence. When more than one candidate fits,
 * nothing is matched and the case is reported as ambiguous. Nothing here is fabricated: unmatched symbols are added/removed.
 */
export interface CorrelatedSymbol {
  path: string;
  kind: SymbolKind;
  qualifiedName: string;
  signatureFingerprint: string | null;
  symbolKey: string;
  contentHash: string;
}

export type MatchBasis = "identical_content" | "same_path_same_name" | "same_name_moved" | "same_signature_renamed";

export interface SymbolMatch {
  before: CorrelatedSymbol;
  after: CorrelatedSymbol;
  basis: MatchBasis;
  inferred: boolean;
  confidence: "certain" | "high" | "medium" | "low";
}

export interface AmbiguousSymbol {
  before: CorrelatedSymbol;
  candidates: CorrelatedSymbol[];
  basis: MatchBasis;
}

export interface CorrelationResult {
  matches: SymbolMatch[];
  added: CorrelatedSymbol[];
  removed: CorrelatedSymbol[];
  ambiguous: AmbiguousSymbol[];
}

const order = (a: CorrelatedSymbol, b: CorrelatedSymbol): number =>
  a.path < b.path ? -1 : a.path > b.path ? 1 : a.qualifiedName < b.qualifiedName ? -1 : a.qualifiedName > b.qualifiedName ? 1 : a.symbolKey < b.symbolKey ? -1 : a.symbolKey > b.symbolKey ? 1 : 0;

function groupBy<T>(items: readonly T[], key: (item: T) => string | null): Map<string, T[]> {
  const map = new Map<string, T[]>();
  for (const item of items) {
    const k = key(item);
    if (k === null) {
      continue;
    }
    const list = map.get(k);
    if (list === undefined) {
      map.set(k, [item]);
    } else {
      list.push(item);
    }
  }
  return map;
}

/**
 * Passes run from strongest to weakest evidence. Within a pass a symbol is matched only when exactly one candidate exists on
 * each side; otherwise every symbol involved is reported as ambiguous and taken out of later passes, so it can never be both
 * matched and ambiguous, and an ambiguous candidate is never also reported as "added". O(n log n): sets and maps, no list scans.
 */
export function correlateSymbols(beforeInput: readonly CorrelatedSymbol[], afterInput: readonly CorrelatedSymbol[]): CorrelationResult {
  const before = [...beforeInput].sort(order);
  const after = [...afterInput].sort(order);
  const matches: SymbolMatch[] = [];
  const ambiguous: AmbiguousSymbol[] = [];
  const matchedBefore = new Set<CorrelatedSymbol>();
  const matchedAfter = new Set<CorrelatedSymbol>();
  const ambiguousBefore = new Set<CorrelatedSymbol>();
  const reservedAfter = new Set<CorrelatedSymbol>();

  const freeBefore = (): CorrelatedSymbol[] => before.filter((s) => !matchedBefore.has(s) && !ambiguousBefore.has(s));
  const freeAfter = (): CorrelatedSymbol[] => after.filter((s) => !matchedAfter.has(s) && !reservedAfter.has(s));
  const take = (b: CorrelatedSymbol, a: CorrelatedSymbol, basis: MatchBasis, inferred: boolean, confidence: SymbolMatch["confidence"]): void => {
    matches.push({ before: b, after: a, basis, inferred, confidence });
    matchedBefore.add(b);
    matchedAfter.add(a);
  };
  const markAmbiguous = (bs: CorrelatedSymbol[], as: CorrelatedSymbol[], basis: MatchBasis): void => {
    for (const b of bs) {
      ambiguous.push({ before: b, candidates: as, basis });
      ambiguousBefore.add(b);
    }
    for (const a of as) {
      reservedAfter.add(a);
    }
  };
  /** One pass: group both sides by `key`; unique 1:1 groups match, groups with several candidates become ambiguous. */
  const pass = (key: (s: CorrelatedSymbol) => string | null, basis: MatchBasis, inferred: boolean, confidence: SymbolMatch["confidence"]): void => {
    const afterGroups = groupBy(freeAfter(), key);
    for (const [k, bs] of groupBy(freeBefore(), key)) {
      const as = afterGroups.get(k);
      if (as === undefined) {
        continue;
      }
      if (bs.length === 1 && as.length === 1) {
        take(bs[0]!, as[0]!, basis, inferred, confidence);
      } else {
        markAmbiguous(bs, as, basis);
      }
    }
  };

  // 1. identical bytes + identical key: the only non-inferred evidence. A file that stayed at its path matches first; identical copies
  //    at several NEW paths cannot say which one is "the" symbol, so that is ambiguous, not certain.
  const afterByContent = groupBy(after, (s) => `${s.contentHash}\0${s.symbolKey}`);
  for (const [k, bs] of groupBy(before, (s) => `${s.contentHash}\0${s.symbolKey}`)) {
    const as = afterByContent.get(k);
    if (as === undefined) {
      continue;
    }
    const samePath = new Set<CorrelatedSymbol>();
    for (const b of bs) {
      const twin = as.find((a) => a.path === b.path && !samePath.has(a));
      if (twin !== undefined) {
        samePath.add(twin);
        take(b, twin, "identical_content", false, "certain");
      }
    }
    const restBefore = bs.filter((b) => !matchedBefore.has(b));
    const restAfter = as.filter((a) => !matchedAfter.has(a));
    if (restBefore.length === 1 && restAfter.length === 1) {
      take(restBefore[0]!, restAfter[0]!, "identical_content", false, "certain");
    } else if (restBefore.length > 0 && restAfter.length > 0) {
      markAmbiguous(restBefore, restAfter, "identical_content");
    }
  }
  // 2. same file, same kind and qualified name (and ordinal): the file changed, the symbol most likely persists
  pass((s) => `${s.path}\0${s.kind}\0${s.qualifiedName}\0${s.symbolKey}`, "same_path_same_name", true, "high");
  // 3. same kind and qualified name in a different file: a move
  pass((s) => `${s.kind}\0${s.qualifiedName}`, "same_name_moved", true, "medium");
  // 4. renamed in place: same file, same kind, same non-null signature fingerprint
  pass((s) => (s.signatureFingerprint === null ? null : `${s.path}\0${s.kind}\0${s.signatureFingerprint}`), "same_signature_renamed", true, "low");

  return {
    matches,
    added: freeAfter(),
    removed: freeBefore(),
    ambiguous
  };
}
