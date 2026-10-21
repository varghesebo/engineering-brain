# Distribution and maintenance

## Runtime baseline (revised 2026-10-21, supersedes "Node 20/22")
**Node 22 LTS (>=22.13) and Node 24. Node 20 is dropped.** Evidence from the npm registry on this date:
| Package | Latest | `engines.node` |
|---|---|---|
| better-sqlite3 | 13.0.3 | >=22 |
| @sourcegraph/scip-typescript | 0.5.1 | >=22.13.0 |
| @modelcontextprotocol/sdk | 1.32.1 | >=18 |
| tree-sitter (native, not chosen) | 0.25.1 | not declared; prebuilds for 6 platform/arch combos observed |
| web-tree-sitter (WASM, chosen) | 0.25.10 pinned (0.27.1 latest failed to load the tested grammars) | not declared; no native build |

Consequences: the dev machine (Node 20.14) must upgrade before Phase 1B. SQLite via **`better-sqlite3`**; `node:sqlite` (Node >=22.5, still experimental) remains a later option. Parsing: **decided — `web-tree-sitter` pinned 0.25.x (WASM) with the official grammar `.wasm` files** (spike S1: faster, lighter, no native addon, no install script; 0.27.1 + third-party grammars failed to load, so versions must be pinned and tested together). Only native dependency: `better-sqlite3` (prebuilds for darwin/linux/linuxmusl/win32 x64+arm64 observed; no install script). Linux/Windows runtime behaviour: not yet tested.

## Native dependencies
Rely on prebuilt binaries for win32/darwin/linux × x64/arm64. Document the matrix, and on missing prebuild or compile failure print an actionable error (toolchain requirements) rather than degrading silently. CI installs and runs on all three OSes in fresh containers/runners. tree-sitter grammars handled the same way.

## Support matrix (target)
| OS | `index` / `context` / `mcp` (strict offline) | `verify` discovery + evidence inspection | `verify --run` (strict) |
|---|---|---|---|
| macOS | v0.1 | v0.1 | only if sandbox self-test passes |
| Linux | v0.1 | v0.1 | only if sandbox self-test passes |
| Windows | **v0.1, fully supported** | v0.1 | **refused (fail closed)** with a clear explanation until an OS isolation mechanism is verified |

Windows is not second-class: only execution of repo test code in strict mode is blocked.

## CLI name
Working project name `engineering-brain`; CLI executable **`engbrain`** (`brain` is taken by npm `@the-brain/cli`). Registry check 2026-10-21: `engbrain` and `engineering-brain` both 404 (unclaimed) on npm; GitHub search for "engbrain" returns 7 repositories (not reviewed). Full npm/GitHub/trademark clearance is required before first public release.

## Supply chain
Pinned versions + lockfile; automated license scan and SBOM (e.g. CycloneDX) in CI; vulnerability review; release provenance (npm provenance / signed artifacts where feasible); reproducible builds where practical; CI never exposes secrets to untrusted test code; **no install scripts that fetch or execute remote code**.

## Lifecycle
Semver for CLI and a separate MCP/tool-schema version. DB: forward-only migrations with automatic pre-migration backup and documented rollback (restore backup). `engbrain uninstall` removes only generated integration/config blocks it created (marked, id-tagged) and reports what remains; deleting persistent knowledge and evidence requires `--purge` with confirmation; never touches source.

## Portability
Config file is repo-relative and portable; paths stored repo-relative with forward slashes; case-insensitive filesystem handling.
