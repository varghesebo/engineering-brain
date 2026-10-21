import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

const src = (p: string): string => fileURLToPath(new URL(p, import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      "@engbrain/security": src("./packages/security/src/index.ts"),
      "@engbrain/core": src("./packages/core/src/index.ts"),
      "@engbrain/cli": src("./packages/cli/src/index.ts")
    }
  },
  test: {
    include: ["packages/*/test/**/*.test.ts", "tests/**/*.test.ts"],
    testTimeout: 60_000,
    hookTimeout: 60_000
  }
});
