# Spike results (observed, 2026-10-21)

Disposable experiments, synthetic fixtures only, run outside the product repo (scratch dir, not committed). Environment: macOS 26.6.2 on arm64 hardware; the Node 22.23.3 binary installed via npm ran as **x64** (so darwin-x64 prebuilds were exercised). Node 22.23.3 only. **Not tested: Linux, Windows, arm64-native Node, Node 24, cold disk cache.** Fixtures: generated TS repos of 100 / 2,000 / 20,000 files (~630 bytes each, 6 functions + 1 class per file).

## S1. Parser: native tree-sitter vs WASM
| | native `tree-sitter` 0.25.1 + `tree-sitter-typescript` 0.23.2 | WASM `web-tree-sitter` 0.25.10 + official grammar `.wasm` |
|---|---|---|
| 2,000 files | 2,406 files/s, RSS 209 MB | 3,161 files/s, RSS 124 MB |
| 20,000 files | 2,363 files/s, RSS 1,563 MB | 4,288 files/s, RSS 143 MB |
| Symbols found (20k) | 180,000 | 180,000 |
| Install | needed `--legacy-peer-deps` (typescript grammar peer-depends on `tree-sitter ^0.21`, conflicting with 0.25.1) | clean |
| Install scripts | `install: node-gyp-build` (prebuilds for 6 platform/arch combos present; works with `--ignore-scripts`) | none |
| Native addon | yes | no |

Caveats: native run did not release trees explicitly (the WASM run called `tree.delete()`), so RSS is not like-for-like; the throughput difference is observed, its cause is not investigated. `web-tree-sitter` **0.27.1 could not load** the third-party `tree-sitter-wasms` 0.1.13 grammars (dylink metadata error); **0.25.x with the official grammar `.wasm` shipped inside `tree-sitter-typescript` works**. Version pairing is therefore fragile and must be pinned and tested.

**Decision: WASM (`web-tree-sitter` pinned 0.25.x + official grammar `.wasm`) is the v0.1 baseline.** Native stays a possible later optimization. Grammar `.wasm` provenance: use the official packages' files (MIT), not third-party bundles (`tree-sitter-wasms` is Unlicense, provenance unclear).

## S2. SQLite: copy-forward vs content-addressed manifest
`better-sqlite3` 13.0.3 (SQLite 3.53.4, FTS5 present, prebuilds for 8 targets incl. win32-x64/arm64, linuxmusl, no install script).
Simplified schemas; one generation with 1% of files changed; 9 symbols + 15 edges per file; WAL.
| 20,000 files | copy-forward (A) | manifest (B) |
|---|---|---|
| Initial index | 623 ms | 925 ms |
| Incremental, 1% changed | **3,021 ms** | **19 ms** |
| Unchanged re-index | 217 ms | 7 ms |
| DB size after 3 generations | 64 MB (~22 MB per extra generation) | 21 MB |
| Read: symbols of one file | 0.004 ms | 0.003 ms |
At 2,000 files: 54 ms vs 2 ms incremental. **Decision: manifest model.** Limits: schema is simplified; edges stored per file (path-level target), so cross-file resolution cost is **not** measured; garbage collection and many-generation retention not measured.

## S3. Freshness checks (20,000-file git repo, warm cache)
| Check | Time |
|---|---|
| `git status --porcelain` (clean) | 88-108 ms |
| `git ls-files` | 64 ms |
| walk 20k files | ~104 ms |
| `stat` 20k files | ~57 ms |
| **SHA-256 of all 20k files** | **~1,030 ms** |
Spoof test (same-size edit, mtime restored): `git status` **did detect** it (git also compares ctime/inode), but a size+mtime-only heuristic would **not**. Whether ctime-based detection holds on all filesystems/OSes (Windows, network FS, `core.trustctime=false`) is unverified. Cold-cache hash time is unmeasured and will be slower.
Conclusion: full hash validation of a 20k-file repo is affordable (~1 s warm) as an explicit check; per-call checks must use the cheaper heuristic and be labelled as such.

## S4. Offline enforcement (macOS only)
- Node 22.23.3 `--permission` did **not** block TCP connect or DNS (connected to loopback, resolved example.com). It must not be relied on for network isolation.
- `sandbox-exec` with `(deny network*)`: TCP -> `EPERM`, DNS -> `ENOTFOUND`; a grandchild process spawned by the sandboxed process was also blocked; filesystem write-deny also worked. Man page marks it **DEPRECATED**.
- Self-test probe pattern works: under a permissive profile the probe connects (=> "not isolated" detected); under deny it fails.
- Linux (bwrap/unshare), Windows (AppContainer/firewall): **not tested**.

## S5. SCIP offline
`@sourcegraph/scip-typescript` 0.5.1 (needs Node >=22.13, Apache-2.0, no lifecycle scripts): ran under `sandbox-exec` deny-network, exit 0, on 100-file (0.98 s, 495 KB) and 2,000-file (2.5 s, 10.3 MB) fixtures; two runs produced identical output (same SHA-1 prefix). Not tested: repos with `node_modules`, memory use, JS-only/`jsconfig` repos, hostile `tsconfig.json`, other SCIP indexers.

## S6. Trusted-computing-base probes
- **Hostile git config executes code:** in a repo with `core.fsmonitor=<script>`, plain `git status` **executed the script**. `git -c core.fsmonitor=false -c core.hooksPath=/dev/null --no-optional-locks status` did not. Every git invocation by engbrain must be hardened (and ideally sandboxed); other config keys that execute commands were **not** audited.
- Native `tree-sitter` works with `npm install --ignore-scripts` (prebuilds loaded at runtime). better-sqlite3 13.0.3 and scip-typescript declare no lifecycle scripts.
