# Ontology and schema (SQLite) — v0.1 decision: content-addressed facts + generation manifests

Supersedes the generation-keyed, copy-forward design (spike S2: copy-forward 3,021 ms vs manifest 19 ms for a 1% change on 20k files). SQLite is sufficient; no graph DB.

## Identities
- `install_id` — random UUID per machine/user profile; never leaves the machine.
- `repository_id` — random UUID written to the store at `engbrain init`. It is **not** derived from remote URL (untrusted) or path. Advisory hint `history_key` = hash of root-commit set, recorded only when the repo is non-shallow and has commits. **Foundation behaviour (deviation D2):** a mismatch is adopted and reported (`historyChanged`), not refused, because rewriting a root commit is legitimate; the store stays bound by install id and real path. Uncommitted repos, shallow clones and non-git directories get the UUID only (`history_key` null).
- `worktree_id` — random UUID per worktree store (one store per worktree at `<worktree-root>/.engineering-brain/` in v0.1; no cross-worktree sharing). Stored with `root_realpath`; a moved/copied store is detected and refused/re-initialised.
- `revision` — HEAD commit SHA (null if none). Detached HEAD is just a revision with no branch label. Branch names are informational labels, never keys. Rebase/cherry-pick change `revision` and file hashes only; unchanged content is reused.
- `dirty_fingerprint` — hash over sorted (path, content_hash) of files that differ from HEAD (modified, untracked, non-excluded).
- `generation_id`, `schema_version`, `completed_at`.

## Tables
Store-level: `store_meta(schema_version, install_id, repository_id, worktree_id, root_realpath, history_key, current_generation_id)`.

Snapshot layer (small, per generation):
- `generations(id, parent_id, revision, branch_label, dirty_fingerprint, extractor_set_hash, status[building|complete|abandoned], created_at, completed_at, hash_verified_at)`
- `generation_files(generation_id, path, content_hash, size, mtime_ns, ctime_ns, inode, excluded_reason)` PK(generation_id, path) WITHOUT ROWID. One row per file; this is the manifest. Paths NFC-normalised, case preserved.

Fact layer (content-addressed, immutable, shared by all generations):
- `file_facts(content_hash, extractor_id, extractor_version, language, parse_status[ok|error|skipped], PK(...))`
- `symbols(content_hash, extractor_id, extractor_version, local_id, kind, name, qualified_name, range)` — identifiers and signatures only; **never literal values** (secret hygiene).
- `syntax_refs(content_hash, extractor_id, extractor_version, local_id, ref_kind[import|call_site|identifier|extends|implements], target_text, range)` — **syntax only; no claim about what the target is**.
- FTS5 tables over symbol names and paths.

Derived layer (generation-scoped, rebuildable):
- `resolutions(generation_id, from_fact_key, from_local_id, to_path, to_symbol_ref, method[import_path|scip|name_match], semantic_certainty[resolved|ambiguous|unresolved])`.
  v0.1 resolves **import specifiers to files only** (deterministic path resolution against the manifest) and, if the optional SCIP adapter is enabled, SCIP-resolved references. **v0.1 makes no claim of resolved call targets from tree-sitter alone.** Import resolutions are recomputed in full per generation (cost proportional to import count; to be benchmarked) — avoids dependency-invalidation logic in v0.1.

Verification layer (separate, never merged into facts):
- `evidence(id, fact_or_generation_ref, source_fingerprint, env_fingerprint, command_id, outcome[passed|failed|skipped|timed_out|incomplete|not_run], started_at, finished_at, details_ref)`.
- `tests(content_hash..., test_id, command_hint)` discovery only.

## Independent dimensions (never one score, never one column)
| Dimension | Question answered | Values | Lives in |
|---|---|---|---|
| `extraction_method` (+ extractor id/version) | how was it produced | tree_sitter_syntax · scip · manual_doc · model | fact rows |
| `semantic_certainty` | how well is the target known | syntactic_only · resolved · ambiguous · unresolved | resolutions / refs |
| `evidence_type` | what kind of source supports it | static_analysis · runtime_observation · documentation · model_inference | fact/memory rows |
| `verification` | did a check pass for this fingerprint | derived from `evidence.outcome`, bound to source+env fingerprint | evidence table |
| `staleness` | still valid? | fresh · stale · invalidated (+reason) | derived at read time |
`verified` is **not** an evidence type: it is a verification outcome. Tree-sitter facts are `extraction_method=tree_sitter_syntax`, `semantic_certainty=syntactic_only` unless resolution upgraded them.

## Generation lifecycle
1. Create `generations` row `building` (own short transaction).
2. Parse changed/new content hashes; insert `file_facts` rows in batches (each batch its own transaction). Facts are immutable and unreferenced until publication, so a crash leaves only orphans.
3. Write `generation_files` manifest, derive `resolutions`, run validation (row counts, manifest ↔ facts completeness, `PRAGMA integrity_check`/`foreign_key_check`).
4. **Publication = one transaction** that sets `status=complete` and `store_meta.current_generation_id`. Readers use a read transaction (WAL snapshot), so they see either the old or the new generation entirely.
5. Startup recovery: any `building` generation is marked `abandoned`; re-index is idempotent.

## Cross-file safety
Facts never reference other facts' rows directly; cross-file links exist only in `resolutions`, which carry `generation_id` and are joined through `generation_files` of the **same** generation. No query may join symbols across generations; enforced by API shape (queries take a generation id) and a test (T3/T5 variants).

## Retention and garbage collection
Keep the last K complete generations (default 3) plus any generation referenced by retained evidence (evidence keeps its fingerprint strings even after the generation is gone, becoming `stale`). GC = delete expired generations + manifests, then delete `file_facts`/`symbols`/`syntax_refs` not referenced by any retained manifest (mark-and-sweep in batched transactions, single writer lock). `VACUUM` only on explicit command. GC at the end of each index run and via `engbrain gc`. GC cost/size growth over many generations: **unmeasured**.

## Later (not v0.1)
`memories` (v0.2): kind, proposed vs approved, inferred vs tested, applicable revision, invalidation rule tied to dependent files/symbols; bi-temporal valid-from/to (idea from Graphiti). Memory never overrides current source.
