/**
 * A small, bounded JavaScript/TypeScript lexer for the entity detectors. It is NOT a parser: it removes comments, understands string, template and
 * regular-expression literals well enough to avoid reading code-looking text inside them, and yields identifiers, literals and punctuation with line numbers.
 * Linear time, no recursion beyond a fixed template nesting depth, hard token cap.
 */
export interface Token {
  /** id | str | tpl (a template literal; `dyn` when it has substitutions) | num | p (punctuation) */
  t: "id" | "str" | "tpl" | "num" | "p";
  v: string;
  line: number;
  /** For `tpl`: true when it contains `${...}` substitutions, which are replaced by `{}` in `v`. */
  dyn?: boolean;
}

export const LEXER_LIMITS = { tokens: 400_000, templateDepth: 4 } as const;

const isIdStart = (c: string): boolean => /[A-Za-z_$\u0080-￿]/.test(c);
const isIdPart = (c: string): boolean => /[A-Za-z0-9_$\u0080-￿]/.test(c);

const COOKED: Record<string, string> = { n: "\n", t: "\t", r: "\r", "0": "\0" };

export function lexScript(source: string): { tokens: Token[]; truncated: boolean } {
  const tokens: Token[] = [];
  let i = 0;
  let line = 1;
  const n = source.length;
  let truncated = false;

  /** Reads a template literal starting after the opening backtick; returns the index after the closing one. */
  const readTemplate = (start: number, depth: number): { end: number; value: string; dyn: boolean; lines: number } => {
    let k = start;
    let value = "";
    let dyn = false;
    let lines = 0;
    while (k < n) {
      const c = source[k]!;
      if (c === "`") {
        return { end: k + 1, value, dyn, lines };
      }
      if (c === "\\") {
        if (source[k + 1] === "\n") {
          lines += 1;
        }
        value += source[k + 1] ?? "";
        k += 2;
        continue;
      }
      if (c === "$" && source[k + 1] === "{") {
        dyn = true;
        value += "{}";
        let braces = 1;
        k += 2;
        while (k < n && braces > 0) {
          const d = source[k]!;
          if (d === "\n") {
            lines += 1;
          }
          if (d === "{") {
            braces += 1;
          } else if (d === "}") {
            braces -= 1;
          } else if (d === "`" && depth < LEXER_LIMITS.templateDepth) {
            const inner = readTemplate(k + 1, depth + 1);
            lines += inner.lines;
            k = inner.end;
            continue;
          } else if (d === '"' || d === "'") {
            const close = source.indexOf(d, k + 1);
            const nl = source.indexOf("\n", k + 1);
            if (close !== -1 && (nl === -1 || close < nl)) {
              k = close;
            }
          }
          k += 1;
        }
        continue;
      }
      if (c === "\n") {
        lines += 1;
      }
      value += c;
      k += 1;
    }
    return { end: n, value, dyn, lines };
  };

  const previousAllowsRegex = (): boolean => {
    const last = tokens[tokens.length - 1];
    if (last === undefined) {
      return true;
    }
    if (last.t === "num" || last.t === "str" || last.t === "tpl") {
      return false;
    }
    if (last.t === "id") {
      return ["return", "typeof", "case", "in", "of", "delete", "void", "throw", "new", "else", "do", "yield", "await"].includes(last.v);
    }
    return ![")", "]", "}", "<"].includes(last.v); // `</div>`: a slash after `<` is a JSX closing tag, not a regular expression
  };

  while (i < n) {
    if (tokens.length >= LEXER_LIMITS.tokens) {
      truncated = true;
      break;
    }
    const c = source[i]!;
    if (c === "\n") {
      line += 1;
      i += 1;
    } else if (c === " " || c === "\t" || c === "\r") {
      i += 1;
    } else if (c === "/" && source[i + 1] === "/") {
      const end = source.indexOf("\n", i);
      i = end === -1 ? n : end;
    } else if (c === "/" && source[i + 1] === "*") {
      const end = source.indexOf("*/", i + 2);
      const stop = end === -1 ? n : end + 2;
      for (let k = i; k < stop; k += 1) {
        if (source[k] === "\n") {
          line += 1;
        }
      }
      i = stop;
    } else if (c === '"' || c === "'") {
      // a string ends at its closing quote or at the end of the line (an apostrophe in JSX text must not swallow the file)
      let k = i + 1;
      let value = "";
      let closed = false;
      let continued = 0; // lines consumed by backslash-newline continuations inside the literal
      while (k < n && source[k] !== "\n") {
        const d = source[k]!;
        if (d === "\\") {
          const e = source[k + 1] ?? "";
          if (e === "\n") {
            continued += 1;
            k += 2;
            continue;
          }
          value += COOKED[e] ?? e;
          k += 2;
          continue;
        }
        if (d === c) {
          closed = true;
          break;
        }
        value += d;
        k += 1;
      }
      if (closed) {
        tokens.push({ t: "str", v: value, line });
        line += continued;
        i = k + 1;
      } else {
        tokens.push({ t: "p", v: c, line });
        i += 1;
      }
    } else if (c === "`") {
      const startLine = line;
      const tpl = readTemplate(i + 1, 0);
      tokens.push({ t: "tpl", v: tpl.value, line: startLine, ...(tpl.dyn ? { dyn: true } : {}) });
      line += tpl.lines;
      i = tpl.end;
    } else if (c === "/" && previousAllowsRegex()) {
      let k = i + 1;
      let inClass = false;
      while (k < n && source[k] !== "\n") {
        const d = source[k]!;
        if (d === "\\") {
          k += 2;
          continue;
        }
        if (d === "[") {
          inClass = true;
        } else if (d === "]") {
          inClass = false;
        } else if (d === "/" && !inClass) {
          break;
        }
        k += 1;
      }
      if (source[k] === "/") {
        k += 1;
        while (k < n && isIdPart(source[k]!)) {
          k += 1;
        }
        tokens.push({ t: "str", v: "", line }); // a regex literal is an opaque value
        i = k;
      } else {
        tokens.push({ t: "p", v: "/", line });
        i += 1;
      }
    } else if (isIdStart(c)) {
      let k = i + 1;
      while (k < n && isIdPart(source[k]!)) {
        k += 1;
      }
      tokens.push({ t: "id", v: source.slice(i, k), line });
      i = k;
    } else if (c >= "0" && c <= "9") {
      let k = i + 1;
      while (k < n && /[0-9A-Za-z_.]/.test(source[k]!)) {
        k += 1;
      }
      tokens.push({ t: "num", v: source.slice(i, k), line });
      i = k;
    } else if (c === "=" && source[i + 1] === ">") {
      tokens.push({ t: "p", v: "=>", line });
      i += 2;
    } else if (c === "." && source[i + 1] === "." && source[i + 2] === ".") {
      tokens.push({ t: "p", v: "...", line });
      i += 3;
    } else {
      tokens.push({ t: "p", v: c, line });
      i += 1;
    }
  }
  return { tokens, truncated };
}
