/** Deterministic SYNTHETIC monorepo for Phase 2B graph tests (original content, no customer data). */
export function graphFiles(): Record<string, string> {
  const files: Record<string, string> = {
    "package.json": JSON.stringify({ name: "graph-root", private: true, workspaces: ["packages/*"] }),
    "tsconfig.json": JSON.stringify({ compilerOptions: { baseUrl: ".", paths: { "@app/*": ["packages/app/src/*"] } } }),
    "packages/core/package.json": JSON.stringify({ name: "@org/core", main: "src/index.ts" }),
    "packages/app/package.json": JSON.stringify({ name: "@org/app", main: "src/main.ts" }),

    // --- core package: barrel, default export, class hierarchy, duplicate names ---
    "packages/core/src/index.ts": 'export * from "./models";\nexport { Logger as Log } from "./logger";\nexport { default as Config } from "./config";\nexport * as helpers from "./helpers";\n',
    "packages/core/src/models.ts": [
      "export interface Walker { walk(): void }",
      "export class Animal { speak(): string { return 'x'; } }",
      "export class Dog extends Animal implements Walker { walk(): void {} bark(): string { return 'woof'; } }",
      "export function dupe(a: number): number { return a; }",
      "export function dupe(a: string): string { return a; }",
      "export class Cat extends Animal {}",
      ""
    ].join("\n"),
    "packages/core/src/logger.ts": "export class Logger { info(m: string): void {} }\nexport function log(m: string): void {}\n",
    "packages/core/src/config.ts": "export default class Config { get(k: string): string { return k; } }\n",
    "packages/core/src/helpers/index.ts": 'export function pad(s: string): string { return s; }\nexport { log } from "../logger";\n',
    "packages/core/src/util.ts": "export function log(m: string): void {}\n",

    // --- app package: workspace import, alias import, heritage across files, CommonJS, dynamic, missing ---
    "packages/app/src/main.ts": [
      'import { Dog, Log, Config, helpers } from "@org/core";',
      'import { Widget } from "@app/widget";',
      'import { a } from "./cycle/a";',
      'import fs from "node:fs";',
      'import { zzz } from "@org/core";',
      'import missing from "./nope";',
      "export class Puppy extends Dog implements Widget { }",
      "export function boot(name: string) { const l = new Log(); const c = new Config(); helpers.pad(name); a(); return import(name); }",
      ""
    ].join("\n"),
    "packages/app/src/widget.ts": "export interface Widget { render(): void }\nexport class Base {}\n",
    "packages/app/src/legacy.js": 'const { log } = require("@org/core");\nconst Config = require("@org/core").Config;\nfunction run() { return log("x"); }\nmodule.exports = { run };\n',
    "packages/app/src/cycle/a.ts": 'import { b } from "./b";\nexport function a() { return b(); }\n',
    "packages/app/src/cycle/b.ts": 'import { c } from "./c";\nexport function b() { return c(); }\n',
    "packages/app/src/cycle/c.ts": 'import { a } from "./a";\nexport function c() { return a(); }\n',
    "packages/app/src/hub.ts": "export const hub = 1;\nexport function hubFn() {}\n"
  };
  for (let i = 0; i < 60; i += 1) {
    files[`packages/app/src/leaf${i}.ts`] = `import { hub, hubFn } from "./hub";\nexport function leaf${i}() { return hub + (hubFn(), ${i}); }\n`;
  }
  return files;
}
