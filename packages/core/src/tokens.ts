/**
 * A deliberately conservative token ESTIMATE: UTF-8 bytes / 3. English prose and source code average 3.5-4.5 bytes per token on common
 * tokenizers, so this over-counts and a budget enforced with it is not exceeded by the real tokenizer. It is not a tokenizer and no model is called.
 */
export function estimateTokens(text: string): number {
  return Math.ceil(Buffer.byteLength(text, "utf8") / 3);
}

/** Tokens of a value as it would be sent: the serialized JSON, so wrapper metadata is counted with the content. */
export function estimateJsonTokens(value: unknown): number {
  return estimateTokens(JSON.stringify(value));
}
