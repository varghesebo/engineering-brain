import { sha256Hex } from "./hash.js";
import { scanForSecrets } from "./secretScan.js";

const BINARY_SNIFF_BYTES = 8192;
const decoder = new TextDecoder("utf-8", { fatal: true });

export type ContentVerdict = { kind: "excluded"; reason: string } | { kind: "ok"; hash: string };

/**
 * The single content policy for bytes that may become facts, whether they come from the working tree or from a
 * git object: binary sniff, strict UTF-8, secret scan, then the content hash. Path-based exclusion and size caps
 * are applied by callers BEFORE the bytes are read. Matched secret text is never returned.
 */
export function evaluateContent(data: Buffer): ContentVerdict {
  if (data.subarray(0, BINARY_SNIFF_BYTES).includes(0)) {
    return { kind: "excluded", reason: "binary_content" };
  }
  let text: string;
  try {
    text = decoder.decode(data);
  } catch {
    return { kind: "excluded", reason: "invalid_utf8" };
  }
  const detector = scanForSecrets(text);
  if (detector !== null) {
    return { kind: "excluded", reason: `secret:${detector}` };
  }
  return { kind: "ok", hash: sha256Hex(data) };
}
