#!/usr/bin/env node
import { nodeVersionProblem } from "./nodeVersion.js";

const problem = nodeVersionProblem();
if (problem !== null) {
  process.stderr.write(`error: ${problem}\n`);
  process.exitCode = 1;
} else {
  // Imported only after the version check: the SQLite native module cannot load on older Node.
  const { main } = await import("./main.js");
  process.exitCode = await main(process.argv.slice(2), {
    stdout: (text) => void process.stdout.write(text),
    stderr: (text) => void process.stderr.write(text),
    env: process.env,
    cwd: process.cwd()
  });
}
