export interface Io {
  stdout(text: string): void;
  stderr(text: string): void;
  env: NodeJS.ProcessEnv;
  cwd: string;
}

/** Exit codes: 0 ok, 1 error, 2 usage, 3 refused by policy. */
export const EXIT = { ok: 0, error: 1, usage: 2, refused: 3 } as const;

export function printJsonOrText(io: Io, json: boolean, value: Record<string, unknown>, text: string): void {
  io.stdout(json ? `${JSON.stringify(value, null, 2)}\n` : `${text}\n`);
}
