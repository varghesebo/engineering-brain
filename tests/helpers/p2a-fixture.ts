/** Deterministic SYNTHETIC multi-module TS/JS repository for Phase 2A tests (original content, no customer data). */
export function p2aFiles(): Record<string, string> {
  return {
    "tsconfig.json": `{
  // comments and trailing commas are legal in tsconfig
  "compilerOptions": { "baseUrl": ".", "paths": { "@app/*": ["src/*"], "@lib": ["packages/lib/src/index.ts"], }, },
}`,
    "package.json": JSON.stringify({ name: "fixture-root", private: true, workspaces: ["packages/*"] }),
    "packages/lib/package.json": JSON.stringify({ name: "@org/lib", main: "src/index.ts" }),
    "packages/lib/src/index.ts": "export function libFn(a: number): number { return a * 2; }\nexport const LIB_VERSION = 1;\n",
    "src/index.ts": 'export * from "./auth";\nexport { helper as utilHelper } from "./util";\nexport * as constants from "./constants";\n',
    "src/constants.ts": "export const TOKEN_TTL = 3600;\nexport const NAME = 'fixture';\n",
    "src/auth/index.ts": 'export { refreshToken } from "./refreshToken";\nexport { default as Session } from "./session";\n',
    "src/auth/refreshToken.ts": [
      'import { helper } from "../util";',
      'import { TOKEN_TTL } from "@app/constants";',
      'import { libFn } from "@org/lib";',
      'import fs from "node:fs";',
      'import lodash from "lodash";',
      "export function refreshToken(token: string, ttl: number = TOKEN_TTL): string {",
      "  function sign(value: string) { return helper(value) + libFn(ttl); }",
      "  const wrap = (v: string) => sign(v);",
      "  return wrap(token);",
      "}",
      "export class TokenStore { private items = new Map<string, string>(); constructor(private limit: number) {} put(k: string, v: string) { this.items.set(k, v); } }",
      ""
    ].join("\n"),
    "src/auth/session.ts": "export default class Session { start(id: string): void {} end(): void {} }\n",
    "src/util.ts": "export function helper(v: string): string { return v.trim(); }\nexport function unused(): void {}\n",
    "src/circular/a.ts": 'import { b } from "./b";\nexport function a(): number { return b() + 1; }\n',
    "src/circular/b.ts": 'import { a } from "./a";\nexport function b(): number { return typeof a === "function" ? 1 : 0; }\n',
    "src/dynamic.ts": 'export async function load(name: string) { const m = await import("./util"); const n = await import(name); const r = require("./constants"); return [m, n, r]; }\n',
    "src/ambiguous.ts": "export const one = 1;\n",
    "src/ambiguous.tsx": "export const two = <div/>;\n",
    "src/useAmbiguous.ts": 'import { one } from "./ambiguous";\nexport const x = one;\n',
    "src/missing.ts": 'import { nope } from "./does-not-exist";\nexport const y = nope;\n',
    "src/components/App.tsx": 'import { Button } from "./Button";\nexport const App = () => <main><Button label="x" /></main>;\nexport default App;\n',
    "src/components/Button.jsx": "export function Button(props) { return <button>{props.label}</button>; }\n",
    "src/legacy.js": 'const { helper } = require("./util");\nfunction legacy(a, b) { return helper(a) + b; }\nmodule.exports = { legacy };\nexports.extra = 1;\n',
    "src/broken.ts": "export function fine() {}\nexport function broken( {{{ \nexport class AfterBroken {}\n",
    "docs/readme.md": "# docs\n",
    "data/config.json": '{"a": 1}\n',
    "scripts/tool.py": "def tool():\n    return 1\n"
  };
}

/** Files that must never reach the index (written in addition to `p2aFiles`, as untracked or ignored content). */
export function p2aExcluded(): Record<string, string> {
  return {
    ".env": "TOKEN=not-a-real-token-value-0000\n",
    "node_modules/pkg/index.js": "module.exports = function pkg() {};\n",
    "dist/out.js": "function built() {}\n",
    "keys/server.pem": "pem-placeholder\n"
  };
}
