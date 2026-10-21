# Architecture review — Phase 1A amendment pass (final, for approval)

No application code, commit, push or publish occurred. Spikes ran as disposable scratch experiments on synthetic fixtures; nothing from them is in the product repo. Observed data: `spike-results.md`. Executable criteria: `acceptance.md`.

## 1. Resolved findings
| Finding | Resolution | Where |
|---|---|---|
| B3 copy-forward cost | **Content-addressed facts + per-generation manifests.** Observed 20k files, 1% change: 19 ms vs 3,021 ms; DB 21 MB vs 64 MB after 3 generations | ontology-and-schema.md, S2 |
| B4 / reviewer #3 freshness | Four levels: `hash_verified`, `heuristic`, `stale`, `unknown`; heuristic never labelled verified; `check_freshness(paths)` tool; race handling documented | incremental-indexing.md, mcp-spec.md |
| B5 offline measurement | Node `--permission` observed **not** blocking network; app-level guarantee tested via static import check + runtime guards; OS isolation only via sandbox with self-test | security.md, S4 |
| B6 sandbox mechanisms | macOS `sandbox-exec` verified for network+children (deprecated by Apple); Linux/Windows untested => `verify --run` and SCIP adapter stay disabled there | security.md |
| #4 TCB | TCB table (install, native addon, WASM parser, git, SCIP, updates); install scripts observed; **hostile `core.fsmonitor` executed under plain `git status`** => hardened git mandatory | security.md, S6, T15–T17 |
| #5 identity | Random `repository_id`/`worktree_id`; root-commit hash only an advisory `history_key`; remote URL not used; handling for no-commit, shallow, detached HEAD, rebase, copied/moved stores | ontology-and-schema.md, T21 |
| #6 provenance | Separate dimensions: extraction_method, semantic_certainty, evidence_type, verification (outcome table). `verified` removed from proof type. Tree-sitter = `syntactic_only`; v0.1 resolves imports only | ontology-and-schema.md |
| #7 secrets/audit/symlink/storage/deletion | Scanner limits + false-negative list + redaction option; audit rotation/retention/hashed paths; symlink rules; local-FS requirement; default uninstall vs `--purge` | security.md, T12/T13 |
| #8 acceptance | `acceptance.md` T1–T21 with fixtures, procedures, thresholds, failure behaviour | acceptance.md |
| Parser decision (S1) | **WASM `web-tree-sitter` 0.25.x + official grammar `.wasm`**: 4,288 vs 2,363 files/s and 143 MB vs 1,563 MB RSS on 20k files, no native addon/install script | distribution.md |
| Node baseline | Node 22 LTS (>=22.13) + 24 | distribution.md |
| SCIP offline (S5) | scip-typescript 0.5.1 ran under network-deny sandbox, deterministic output; adapter stays optional with a per-adapter go/no-go | security.md class C |
| Smaller items (WAL/local FS, dedup optional, test outcomes split, onboarding version table, uninstall default) | applied | respective docs |

## 2. Final v0.1 schema decision
Store per worktree at `<root>/.engineering-brain/`. Tables: `store_meta`, `generations`, `generation_files` (manifest), `file_facts`/`symbols`/`syntax_refs` (immutable, keyed by content hash + extractor version), `resolutions` (generation-scoped, imports only in v0.1), `evidence`, `tests`, FTS5. Publication is a single transaction; readers use a WAL snapshot; `building` generations are abandoned on recovery; retention K=3 plus evidence references; GC by mark-and-sweep.

## 3. Remaining limitations and accepted risks
- **Unverified on Linux and Windows:** runtime behaviour of everything, sandboxing, ctime-based change detection, lock semantics. Only macOS (Node 22.23.3 x64 under arm64 hardware) was exercised; Node 24 untested.
- `sandbox-exec` is deprecated; may disappear. Accepted for v0.1 as an optional capability; the product must not depend on it.
- better-sqlite3 (native, full-privilege in-process) is an accepted TCB element, mitigated by pinning/audit/SBOM only.
- Secret scanning will have false negatives (tracked, not hidden).
- Heuristic freshness can be wrong; it is always labelled and `hash_verified` is available (~1 s per 20k files warm; cold unmeasured).
- Cross-file resolution cost, GC behaviour over many generations, and memory under SCIP are unmeasured.
- Hostile-git hardening covers `core.fsmonitor` and hooks only as tested; **other command-executing git config keys are not exhaustively audited** (T15 must grow).
- Prompt injection cannot be fully prevented by labeling; the control is the absence of write/exec tools.
- Token savings are unproven until the benchmark runs.

## 4. Updated acceptance criteria
See `acceptance.md` (T1–T21 + benchmark list + report format). T15–T21 are new from this pass.

## 5. Go / no-go for the implementation foundation
**GO (conditional)** for the foundation increment only: repo scaffold, hardened-git module, repository/worktree identity, SQLite schema + generation publication, exclusion/secret scanner, WASM parser indexing, stdio MCP read tools, and the T1–T6, T9, T12, T13, T15–T21 tests, once you approve and these preconditions hold:
1. Dev machine upgraded to Node 22 LTS (currently 20.14).
2. `acceptance.md` approved.
3. A Linux and a Windows CI runner available to run the same suite (otherwise those OSes are labelled "untested", not "supported").
**NO-GO (deferred, disabled by default):** SCIP adapter, `verify --run`, any claim of OS-level isolation outside macOS, org-hosted mode, memory/impact/test selection.

## 6. Dependencies still unverified
Grammar `.wasm` + web-tree-sitter version pairing beyond 0.25.10/0.23.2 (pin and CI-test); MCP SDK behaviour with Claude/Codex on chosen versions; Windows prebuild loading for better-sqlite3 and WASM under Node 22/24; Linux sandbox tooling; license/SBOM scan results of the full transitive tree (not yet run); GitHub/npm/trademark clearance for `engbrain`; real-agent token-savings.

## 7. Process notes
- Three setup mistakes in this pass were caught and are recorded here rather than hidden: zsh loop splitting made the first fixture run produce empty repos (regenerated), the first native install failed on a peer-dependency conflict (reported as a finding), and the first WASM run failed with the wrong grammar bundle (diagnosed; official grammar works).
- Spike scripts live in the session scratch directory, not in the product repo, and are not production code.

**Stopped for review.**
