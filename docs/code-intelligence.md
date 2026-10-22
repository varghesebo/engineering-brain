# Code intelligence (Phase 2A; graph layer: see `graph.md`)

Implemented on top of the Foundation: same SQLite store, same content-addressed facts, same atomic generations, same lock and
repository identity. Nothing here is MCP, commit-history analysis or verification. The Phase 2B dependency graph built on these facts is described in `graph.md`.

## Model
- **Facts are content-derived.** They are keyed by `(content_hash, extractor_id, extractor_version)` and never contain a file path or a path-derived label
  (language is derived from the path at read time). Identical bytes extracted by the same extractor version share one set of facts, across paths, branches and generations.
- **The grammar is part of the extractor identity.** There is one code extractor per grammar (`code:ts-wasm:typescript` for `.ts/.mts/.cts`, `code:ts-wasm:tsx` for
  `.tsx/.jsx/.js/.mjs/.cjs`). Each extractor records the path suffixes it applies to with the generation (`generation_extractor_extensions`), and EVERY join from a path to
  facts goes through the view `applicable_facts`. So identical bytes at `real.ts` and `notes.txt` can never poison each other, and an unsupported path gets no fact at all.
  (An earlier version cached facts by content alone while choosing the grammar by path; the independent review reproduced a `.ts` file inheriting a `skipped` fact from an identical `.txt`.)
- **Occurrences and relationships are path-dependent.** A symbol *occurrence* is a fact seen at a path where its extractor applies (view `symbol_occurrences`). Module relationships
  (`module_edges`) are computed per generation because resolution depends on which paths exist and on tsconfig/package.json at that snapshot.
- **Versions are explicit.** The extractor version includes the `web-tree-sitter` and `tree-sitter-typescript` package versions, so upgrading either produces new facts instead of mixing old
  and new. The resolver has its own `resolver_version` on each generation; `status` / `index --check` report `stale` when this build's extractor set or resolver differs from the one that built the index.

## Schema (migrations v2 and v3, forward-only, pre-migration backup)
| Table / view | Keyed by | Holds |
|---|---|---|
| `symbols` | fact key + `local_id` | kind, name, qualified name, parent (`parent_local_id`), `symbol_key`, line/column and UTF-8 byte ranges, signature fingerprint, export flag/name, anonymous flag, parameters JSON |
| `syntax_refs` | fact key + `local_id` | import / export_from / require / dynamic_import, literal target or NULL (unknown), imported names |
| `exports` | fact key + `local_id` | named, default, reexport, reexport_all, reexport_namespace, commonjs |
| `fact_diagnostics` | fact key + `local_id` | severity, code, generic message (never source text), position |
| `module_edges` | generation + path + ordinal | resolution (`resolved/external/unresolved/ambiguous/dynamic`), resolved path, reason; immutable once its generation is published (triggers) |
| `generation_extractor_extensions` | generation + extractor + suffix | the path suffixes each extractor applies to (no rows = every file) |
| `applicable_facts` (view) | generation + path + extractor | the single path-to-fact join, honouring applicability |
| `symbol_occurrences` (view) | generation + path | symbols joined through `applicable_facts` |
All fact tables cascade from `file_facts`, so garbage collection removes dependent rows. Validation before publication checks
that every applicable (path, extractor) pair has a fact and that module edges equal syntactic references for the generation.

## Symbol identity
`symbol_key` = hash(kind, qualified name, ordinal among identical ones in that file): deterministic and stable for identical content,
distinguishes duplicate names. It is **not** a cross-version identity. `correlateSymbols()` (core) compares two versions and returns matches
with a basis: only `identical_content` is non-inferred; `same_path_same_name` (high), `same_name_moved` (medium) and
`same_signature_renamed` (low) are marked `inferred: true`. Ambiguous candidates produce no match.

## Resolver rules (`moduleResolver.ts`)
Relative specifiers: exact, TS ESM mapping (`./a.js` -> `a.ts/.tsx/.d.ts`), appended extensions, directory `index.*`; the first level
with a candidate wins. **Ambiguous** only when different module families both exist (e.g. `x.ts` and `x.tsx`); `x.ts` + compiled `x.js` is resolved
to the source. `tsconfig.json`/`jsconfig.json`: `paths` (most specific pattern), `baseUrl`, relative `extends` inside the repository (depth 5), nearest
config by directory. Workspace packages: only packages declared by a workspace root (`package.json` `workspaces` globs incl. negations, or `pnpm-workspace.yaml` `packages:`) count; their `name` + `main/module/types`, `src/index`, `index` and deep subpaths resolve, and two packages with the same name are `ambiguous`. Node builtins are checked first and can never be shadowed by a workspace package or alias. A `paths` mapping with a literal prefix whose target is missing is `unresolved`; a catch-all `"*"` mapping falls through to normal resolution. Extensionless specifiers never resolve to `.json`. Other bare specifiers are `external` (with the package name). Configuration sizes are capped (1,000 path patterns, 2,000 workspace packages). URLs, absolute paths, `#imports` and empty specifiers are `unresolved`. A non-literal `import(x)` /
`require(x)` is `dynamic`: explicitly unknown. Config files are read only if their bytes still equal the manifest hash (a mismatch aborts the run instead of mixing snapshots), size-capped, parsed as JSONC
without evaluating anything, and can never point outside the repository root.

## Incremental behaviour and freshness
Unchanged content is not re-parsed (tested: second run parses 0; one edited file parses exactly 1). Deleted files drop out of the active generation; a
rename reuses facts and is counted as a rename; importers are re-resolved. Clean and incremental indexing produce identical symbols, exports, edges and
fingerprints (12 seeded mutation runs). Files under excluded directories (`node_modules`, `dist`, `.git`, ...) are pruned in both the git listing and
the directory walk, so the manifest does not depend on how the tree was listed.
Freshness (`status`, `index --check`) states what was established: `heuristic` (git file list + size/mtime/ctime/inode), `hash_verified` (every file re-read
and compared), `stale` (with changed paths), or `unknown`. A file watcher is not used as proof.

## Measured benchmarks (synthetic repositories, this machine)
Environment: macOS, Node 22.23.3 running as `darwin-x64`, single process, warm filesystem cache. Synthetic files: ~25 lines, ~13 symbols and ~4 imports each
(symbol-dense; **TypeScript only**, the generator does not produce JavaScript). RSS includes a ~110 MiB runtime baseline. Reproduce with
`node tests/bench/index-bench.mjs <files> <dir>` after building. Re-measured after Phase 2B and its review fixes: the generator now adds per-directory barrels, barrel imports,
name references and `extends` (about 15 symbols and 12 graph edges per file), so these rows include graph construction and are not comparable to the earlier 2A-only numbers.
"Peak RSS" is the peak at the end of the initial index (the benchmark process peak over all steps was 147 / 241 / 767 MiB).

| Files | Initial index | Files/s | Symbols | Graph edges | DB size | Peak RSS | Unchanged re-index | One-file change | Freshness heuristic / verified | Symbol search p95 |
|---|---|---|---|---|---|---|---|---|---|---|
| 100 | 504 ms | 299 | 1,513 | 1,199 | 2.0 MiB | 132 MiB | 119 ms | 135 ms | 102 / 89 ms | 0.52 ms |
| 2,000 | 2.76 s | 744 | 30,284 | 24,270 | 52.3 MiB | 205 MiB | 386 ms | 1.17 s | 119 / 271 ms | 5.6 ms |
| 20,000 | 36.2 s | 554 | 302,856 | 242,842 | 398.7 MiB | 445 MiB | 2.69 s | 13.8 s | 283 / 1,719 ms | 97 ms |
In every size a one-file change re-parsed exactly 1 file and reused the facts of all others. The 100-file initial time includes WASM startup. Not measured: cold
disk cache, repositories over 20,000 files, other platforms, real-world (non-synthetic) code, JavaScript-heavy repositories.

## Known limitations
- **Parsing is single-threaded** (WASM in-process). "Bounded concurrency" is 1 by design; memory is bounded by 500-fact batches and a 1 MiB per-file cap. There is no
  configurable memory limit and no worker pool yet. A WASM runtime trap is not recovered mid-run (an adapter exception is contained per file).
- **Every index run re-reads and hashes all files** (no metadata fast path); the unchanged run is 2.1 s at 20,000 files. Module and graph edges are recomputed in full per generation (about 11 s at 20,000 files with barrels and heritage; incremental reuse is deferred to H5).
- **Symbol search is a substring scan** (no FTS5 yet): linear in symbols (87 ms p95 at 263k symbols).
- **Resolution is syntactic.** No `node_modules` lookup, no `package.json` `exports` conditions or `#imports`, no tsconfig `include`/`files`/project references,
  `extends` only by relative path. `.js/.mjs/.cjs` use the TypeScript grammar; unusual JS dialects (e.g. Flow) can produce error facts.
- **Not extracted:** declaration merging, class fields that are not functions, object-literal methods, decorators, call targets (no call graph is built
  or implied), JSX component usage. `export =`, `import x = require()`, ambient (`declare`) declarations and destructured exports ARE extracted.
- **Columns** are in UTF-16 code units (a BOM counts as column 1), lines are 1-based, byte offsets are UTF-8. Facts never contain literal values beyond import/export specifiers (parameter names are identifier-only).
- **Platforms:** macOS/Node 22 only. Linux, Windows and Node 24 are untested.
- No OS sandbox is relied on for indexing or MCP. The only subprocesses are hardened git and, from Sentinel 3A, an opt-in execution module (sandbox self-test and a fixed synthetic worker; it needs an explicit, expiring operator authorization and a verified sandbox, and never runs repository code in this build).
- `tree-sitter-typescript` ships an install script (`node-gyp-build`) for a native addon this project never loads; install with `--ignore-scripts`. On platforms without prebuilds, a plain install may fail.

## Independent review (fresh reviewer agent, not Codex)
Codex was not available; per the user's instruction ("No codex so use codex prompt by you itself") a separate Claude agent reviewed the working tree read-only. It is a
different context but the same model family, so this is NOT an independent audit in the strict sense. It reported 15 confirmed findings (and some plausible ones); all
confirmed findings were fixed and covered by regression tests:
path-dependent facts under a content key (HIGH), dropped `export declare` (HIGH), namespace exports leaking to module level, `import = require`/`export =`, literal values in
parameter names, workspace packages shadowing builtins / duplicates / stray `package.json`, `paths` catch-all fall-through, unescaped terminal control characters, freshness not
noticing extractor/resolver changes, config files not hash-checked, inconsistent correlation passes and O(n^2) cost, git-vs-walk disagreement for files named like excluded directories,
smaller extraction gaps, missing dependency versions in the extractor version, and unbounded resolution cost on hostile configuration. See the regression tests
`packages/core/test/reviewFixes.test.ts` and `tests/acceptance/p2a-code-intelligence.test.ts` (section "P2A review regressions").
