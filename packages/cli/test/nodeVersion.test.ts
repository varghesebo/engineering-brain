import { describe, expect, it } from "vitest";
import { nodeVersionProblem } from "../src/nodeVersion.js";

describe("node version gate", () => {
  it.each(["22.13.0", "22.23.3", "24.0.0", "26.1.0"])("accepts %s", (v) => {
    expect(nodeVersionProblem(v)).toBeNull();
  });
  it.each(["20.14.0", "22.12.9", "18.0.0", "21.7.3"])("rejects %s with a clear message", (v) => {
    expect(nodeVersionProblem(v)).toContain("requires Node.js 22.13.0");
  });
  it("accepts the running test runtime", () => {
    expect(nodeVersionProblem()).toBeNull();
  });
});
