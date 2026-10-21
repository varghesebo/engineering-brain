/**
 * Secret-scanning FOUNDATION. Pattern + entropy detection cannot find every secret: false negatives WILL
 * occur (see tests/fixtures/secret-scan-known-gaps.md) and false positives are accepted on the safe side.
 * A match only yields a detector id. The matched text is never returned, stored or logged.
 *
 * Input is hostile. Every pattern is linear-time by construction: all quantifiers are bounded, each pattern
 * starts at a literal/word-boundary anchor, and token-shaped detectors run over delimiter-split tokens (a
 * first version used an unbounded `[a-z0-9+.-]*` scheme prefix and stalled for minutes on a 1 MiB file of
 * "a.a.a." — see the ReDoS test).
 */
interface Detector {
  id: string;
  pattern: RegExp;
}

const DETECTORS: Detector[] = [
  { id: "private_key_block", pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/ },
  { id: "aws_access_key_id", pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { id: "github_token", pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/ },
  { id: "slack_token", pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,100}\b/ },
  { id: "google_api_key", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { id: "stripe_live_key", pattern: /\b[sr]k_live_[0-9A-Za-z]{16,100}\b/ },
  { id: "sk_style_api_key", pattern: /\bsk-[A-Za-z0-9_-]{20,200}\b/ },
  { id: "url_credentials", pattern: /\b[a-z][a-z0-9+.-]{0,19}:\/\/[^/\s:@]{1,100}:[^/\s:@]{1,100}@/i },
  {
    id: "credential_assignment",
    pattern: /\b(?:api[_-]?key|secret|passwd|password|token|auth)[A-Za-z0-9_-]{0,40}\s{0,5}[:=]\s{0,5}["'][^"'\s]{12,500}["']/i
  }
];

/** Maximal runs of token characters (including dots): linear to enumerate, then tested anchored. */
const TOKEN_RUN = /[A-Za-z0-9_.+/=-]{20,}/g;
const JWT = /^eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/;
const ENTROPY_CANDIDATE_MIN = 40;
const ENTROPY_SCAN_LIMIT = 4096;
const ENTROPY_THRESHOLD_BITS = 4.5;

function shannonEntropy(text: string): number {
  const counts = new Map<string, number>();
  for (const char of text) {
    counts.set(char, (counts.get(char) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / text.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** Returns the id of the first detector that fires, or null. Never returns matched content. */
export function scanForSecrets(text: string): string | null {
  for (const detector of DETECTORS) {
    if (detector.pattern.test(text)) {
      return detector.id;
    }
  }
  for (const match of text.matchAll(TOKEN_RUN)) {
    const run = match[0];
    if (JWT.test(run)) {
      return "jwt";
    }
    if (run.length >= ENTROPY_CANDIDATE_MIN && shannonEntropy(run.slice(0, ENTROPY_SCAN_LIMIT)) >= ENTROPY_THRESHOLD_BITS) {
      return "high_entropy_token";
    }
  }
  return null;
}
