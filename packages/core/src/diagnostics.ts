export type LogLevel = "debug" | "info" | "warn" | "error";
export type LogFields = Record<string, string | number | boolean | null>;

const ORDER: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };

export interface Logger {
  debug(message: string, fields?: LogFields): void;
  info(message: string, fields?: LogFields): void;
  warn(message: string, fields?: LogFields): void;
  error(message: string, fields?: LogFields): void;
}

/**
 * Structured local diagnostics. Writes to a caller-supplied sink (stderr in the CLI) and nowhere else.
 * Callers pass ids/counts/codes; source text and secrets must never be passed in.
 */
export function createLogger(write: (line: string) => void, level: LogLevel = "info", json = false): Logger {
  const emit = (at: LogLevel, message: string, fields: LogFields = {}): void => {
    if (ORDER[at] < ORDER[level]) {
      return;
    }
    if (json) {
      write(`${JSON.stringify({ level: at, message, ...fields })}\n`);
      return;
    }
    const suffix = Object.entries(fields).map(([key, value]) => `${key}=${String(value)}`).join(" ");
    write(`${at}: ${message}${suffix === "" ? "" : ` (${suffix})`}\n`);
  };
  return {
    debug: (message, fields) => emit("debug", message, fields),
    info: (message, fields) => emit("info", message, fields),
    warn: (message, fields) => emit("warn", message, fields),
    error: (message, fields) => emit("error", message, fields)
  };
}
