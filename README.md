# engineering-brain

Privacy-first, local-first repository intelligence for AI coding agents. **Status: Foundation stage only**
(pre-release, not usable for agent context yet). Licensed Apache-2.0.

What exists now: the `engbrain` CLI with `init`, `index`, `status`, `gc` and `uninstall`; a per-worktree SQLite
store with content-addressed facts and atomically published, immutable generation snapshots; hardened git access;
exclusions and a secret-scanning foundation; a content-free local audit log. Parsing, retrieval, MCP, freshness
checks, memory and test execution are **not** implemented.

Privacy, stated precisely: engbrain's own code makes no network calls (enforced by tests). It does **not** provide
OS-level isolation for third-party code or child processes, and it cannot control what hosted AI agents transmit.

Requires Node.js 22.13+ (the SQLite native module needs it). Design documents are in `docs/`.

```
npm install --ignore-scripts
npm test          # builds, then runs the full suite
```
