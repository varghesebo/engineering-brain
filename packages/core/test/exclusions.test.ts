import { describe, expect, it } from "vitest";
import { createExclusionMatcher } from "../src/exclusions.js";

describe("default exclusions (deny by default)", () => {
  const matcher = createExclusionMatcher();
  it.each([
    [".env", "sensitive_path"], ["config/.env.production", "sensitive_path"], ["keys/server.pem", "sensitive_path"],
    ["home/.ssh/id_rsa", "sensitive_path"], ["a/b/credentials.json", "sensitive_path"], ["infra/terraform.tfstate", "sensitive_path"],
    [".NPMRC", "sensitive_path"],
    ["node_modules/x/index.js", "excluded_directory"], [".git/config", "excluded_directory"], [".engineering-brain/store.db", "excluded_directory"],
    ["dist/app.js", "excluded_directory"],
    ["package-lock.json", "generated"], ["x/app.min.js", "generated"],
    ["debug.log", "log"], ["img/logo.PNG", "binary_extension"], ["lib/native.dll", "binary_extension"]
  ])("excludes %s as %s", (path, reason) => {
    expect(matcher.excludesPath(path)).toBe(reason);
  });
  it("keeps ordinary source", () => {
    for (const path of ["src/app.ts", "README.md", "docs/guide.md", "src/environment.ts"]) {
      expect(matcher.excludesPath(path)).toBeNull();
    }
  });
  it("custom patterns are additive and cannot re-include defaults", () => {
    const custom = createExclusionMatcher(["docs/**"]);
    expect(custom.excludesPath("docs/guide.md")).toBe("config_exclude");
    expect(custom.excludesPath(".env")).toBe("sensitive_path");
    expect(custom.excludesPath("src/app.ts")).toBeNull();
  });
  it("prunes known directories when walking", () => {
    expect(matcher.excludesDirectory("node_modules")).toBe(true);
    expect(matcher.excludesDirectory("src")).toBe(false);
  });
});
