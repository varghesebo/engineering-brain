# Security and privacy enforcement

## Three separate guarantees (never conflated)
| # | Guarantee | Enforced by | v0.1 status |
|---|---|---|---|
| 1 | engbrain's **own code** makes no outbound network calls | Application design + tests: our packages import no network modules (static check), no telemetry/crash upload/update check, runtime guards in test builds fail on use of `net/dns/http/https/tls/dgram/fetch` | Achievable; tested (T7) |
| 2 | **Third-party code and child processes** (parser, optional indexers, git, test runners) cannot make outbound calls | In-process dependencies: **not enforceable by Node** (see below) -> dependency audit/pinning. Child processes: OS isolation with a startup self-test | Per-OS; only macOS partially verified |
| 3 | Connected cloud agents do not transmit code | Outside our control | Documented, not claimed |

## Observed facts about enforcement (spike S4, macOS 26.6.2, Node 22.23.3)
- Node's `--permission` model did **not** block network. Do not use it as a network boundary.
- `sandbox-exec (deny network*)` blocked TCP and DNS for the process and its children; the self-test probe distinguishes isolated from non-isolated. It is **deprecated** by Apple.
- Linux and Windows mechanisms: **not yet tested**.

## Policy: strict mode never silently falls back
Operation classes in strict offline mode:
| Class | Examples | Rule |
|---|---|---|
| A. Pure in-process | tree-sitter WASM parsing, SQLite, retrieval, MCP stdio | Allowed everywhere, covered by guarantee 1 plus the dependency audit (they run in our process; a malicious dependency could still open sockets — mitigated by pinning, license/vuln review, minimal dependency set, and not by Node permissions) |
| B. Hardened git | `ls-files`, `status`, `rev-parse` with the hardening flags in `incremental-indexing.md` | Allowed; hardened options mandatory; run under the sandbox where available |
| C. Spawns repo-influenced child (optional SCIP indexers, anything reading repo build config) | `scip-typescript` | Allowed **only** if the sandbox self-test passes on this machine in this run; otherwise the adapter is disabled with an explanation. Tree-sitter baseline keeps working |
| D. Executes repo test code | `verify --run` | Same rule as C, plus explicit authorization |
Unsupported privileged operations **fail closed** with a message; indexing and retrieval (class A/B) are never blocked because C/D are unavailable. Windows v0.1: A/B fully supported; C/D refused until a verified mechanism exists.

## Trusted computing base (what we must trust)
| Component | Risk | Control |
|---|---|---|
| npm install of our package | lifecycle scripts, compromised dependency | Minimal deps; observed: better-sqlite3 13.0.3, scip-typescript 0.5.1 and web-tree-sitter have no install scripts; native tree-sitter's `node-gyp-build` script is avoided by choosing WASM. Install with `--ignore-scripts` documented and CI-tested; pinned versions + lockfile; SBOM; no remote fetch in install |
| better-sqlite3 (native addon, has full process privileges) | unlimited in-process capability | Pin, verify prebuilt provenance/checksums, audit upgrades, SBOM; accepted risk |
| web-tree-sitter + grammar `.wasm` | parser crash/DoS on hostile files; WASM sandboxes memory but runs in our process | Official grammar files only; per-file size/time caps; parse in a worker with a timeout so a crash/hang is contained; unparseable file => `parse_status=error` |
| git | executes config-defined commands (observed: `core.fsmonitor`) | Hardened invocation, minimal env, sandbox where available |
| Optional language indexers (SCIP) | read repo-provided `tsconfig`/build config; may spawn tools | Class C rules; per-adapter audit before enabling; allowlist of adapter binaries; never run `postinstall`/package-manager commands |
| Dependency updates | silent behaviour change | Lockfile; Renovate-style PRs reviewed; no auto-update at runtime |

## Storage boundary
Index, temp files, SQLite WAL/SHM, crash dumps, verification artifacts and logs live under `.engineering-brain/` (or an org-approved local dir); temp dir set inside it; best-effort disable of core dumps; no writes elsewhere (T6/T13 variants). Local filesystem required. File mode 0600/dir 0700 where the OS supports it.

## Exclusions and secret scanning (with stated limits)
Default deny: `.env*`, key/cert files, credential files, `.git` internals, generated, logs, binaries; plus org-configurable allow/deny. Content scanning (patterns + entropy) over files **and derived text** before indexing; matches exclude the file and record only `excluded_reason`.
**Limits:** regex/entropy scanning cannot guarantee detection of every secret (false negatives will occur; also false positives). Mitigations: store identifiers/signatures only, never literal values; an `engbrain scan-report` listing excluded files and detector coverage; optional redaction mode that stores no signature text; test fixtures with known-hard secrets and a **tracked false-negative list**. We do not claim secrets cannot appear in the index.

## Symlinks and paths
Resolve `realpath`; reject targets outside the root; do not follow symlink directories; reject path components `..`, NUL, non-UTF8/invalid names (record as excluded); NFC-normalise; case-collision detection; Windows reserved names handled.

## Audit log
Local append-only file; content-free events (type, ids, counts, durations — not source text; paths hashed by default because path names can be sensitive; an option to log plain paths); mode 0600; size-based rotation (default 5 × 5 MB) and retention (default 90 days); never uploaded; `engbrain uninstall --purge` deletes it.

## Data deletion
`engbrain uninstall` (default) removes only generated integration/config blocks we created and reports what remains. Deleting **persistent knowledge and evidence** requires an explicit `--purge` and confirmation; the source repository is never touched.

## Hostile-repo handling
Repo content is untrusted data: never executed by indexing; prompt-injection mitigation = labeling, no tool authority derived from content, and **no write/exec MCP tools** (the hard control; labeling alone is weak).
