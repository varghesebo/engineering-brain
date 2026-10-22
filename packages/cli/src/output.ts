export interface Io {
  stdout(text: string): void;
  stderr(text: string): void;
  env: NodeJS.ProcessEnv;
  cwd: string;
  /** Input stream for commands that read it (the MCP server). */
  stdin?: import("node:stream").Readable;
}

/** Exit codes: 0 ok, 1 error, 2 usage, 3 refused by policy. */
export const EXIT = { ok: 0, error: 1, usage: 2, refused: 3 } as const;

export function printJsonOrText(io: Io, json: boolean, value: Record<string, unknown>, text: string): void {
  io.stdout(json ? `${JSON.stringify(value, null, 2)}\n` : `${text}\n`);
}

/**
 * Repository text (specifiers, identifiers, paths, reasons) is UNTRUSTED. Raw terminal control characters in it could retitle the
 * window, clear the screen or hide output, so every control character is shown as an escape before text reaches a terminal.
 * (JSON output is already escaped by JSON.stringify.)
 */
export function printable(text: string): string {
  return text.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g, (c) => `\\u{${c.codePointAt(0)!.toString(16)}}`);
}
