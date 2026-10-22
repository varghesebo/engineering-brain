# Commit refresh protocol (Wave 1)

Git is the source of commit identity. Content hashes + extractor versions are the identity of parsed facts.
Commit metadata (subject, author) is untrusted description, stored truncated and labelled; it is never evidence.

## Tables (migration v3)
- `git_commits(commit_oid PK, object_format, tree_oid, author_time, committer_time, availability, subject, ingest_complete, first_run_id)`
  - `availability`: `full` | `shallow_boundary` (a parent is absent locally) | `oversized` (parent count over cap).
- `commit_parents(commit_oid, ordinal, parent_oid, PK(commit_oid, ordinal))`. A parent may be absent from `git_commits`.
- `commit_changes(commit_oid, parent_ordinal, path, old_path, change_kind, old_blob, new_blob, old_content_hash, new_content_hash, rename_score, excluded_reason, PK(commit_oid, parent_ordinal, path))`
  - Per-parent rows for merges (parent-aware); the root commit uses `parent_ordinal = -1`.
- `commit_symbol_deltas(commit_oid, parent_ordinal, path, delta, kind, name, qualified_name, signature_fingerprint, candidate_rename_of)`
  - `delta` is `added` or `removed`. `candidate_rename_of` is only a **candidate** (never asserted).
- `blob_hashes(blob_oid PK, object_format, content_hash, size, excluded_reason)`: cache of git blob id to sha256 of bytes (or exclusion).
- `refresh_runs(id, ref_key, from_oid, to_oid, history_mode, status, generation_id, started_at, finished_at, stats_json)`
- `history_checkpoints(ref_key PK, processed_oid, generation_id, run_id, updated_at)`: the **published** position. Readers only see history reachable from `processed_oid`.
- `lineage_events(id, run_id, ref_key, kind, old_oid, new_oid, fork_oid, detail_json, observed_at)`: `baseline | advance | switch | rewrite | unrelated | head_unborn | base_missing`.

## Algorithm (`engbrain refresh`)
1. **Preflight** (hardened git only): HEAD oid, branch label, shallow flag, object format; ref key `HEAD` (the store is per worktree).
2. **Plan** against `history_checkpoints`:
   - no checkpoint -> `baseline`: ingest HEAD only (`--history=none`, default) or all reachable up to `--max-commits` (`--history=backfill`; sets `history_partial` if capped or shallow).
   - `processed == HEAD` -> nothing to ingest.
   - checkpoint is an ancestor -> `advance`: `rev-list --topo-order --reverse --parents processed..HEAD` (parents before children; no timestamp ordering).
   - not an ancestor and object present -> `switch` (branch label changed) or `rewrite`: fork = `merge-base`; ingest `fork..HEAD`; no fork -> `unrelated`.
   - checkpoint object missing locally -> `base_missing`: ingest from HEAD, bounded, `history_partial`.
3. **Ingest** in batches (default 100 commits). Each batch is one transaction and marks `ingest_complete`, so a crashed
   run resumes without redoing finished commits. For each commit: parse the raw commit object (`cat-file --batch`);
   `diff-tree -r -z -M --raw` per parent; classify paths with the same exclusion/secret policy as `index`;
   resolve blobs through `blob_hashes`; extract facts only for blobs lacking facts for the current extractor set;
   write `commit_changes` and symbol deltas.
4. **Overlay**: dirty state is `overlay_hash` = hash of (path, disk content hash) for files whose git blob id (computed
   from disk bytes) differs from HEAD's tree entry, plus untracked files and deletions. Uncommitted changes never get a commit id.
5. **Build + publish**: the existing disk-based generation build runs under the same lock. In the publish transaction the
   generation becomes complete AND `history_checkpoints`/`refresh_runs` advance. If the generation is unchanged the
   checkpoint still advances in its own transaction.
6. **Report**: commits ingested, files changed, blobs read vs reused, extractor runs, lineage event, flags
   (`history_partial`, `truncated`), duration and RSS. No "everything analysed" wording.

## Read API: `changesSince(db, { since })`
`since` = a commit oid, or `last-refresh`. Returns commits reachable from the published `processed_oid` and not from
`since` (recursive CTE over `commit_parents`, so it never consults git and never leaks unrelated branches), with
changes, symbol deltas, lineage events, `relation` (`ancestor | rewritten | unrelated | unknown_base`) and
`historyPartial`. Bounded by `limit`.

## Safety rules
- New git subcommands (`diff-tree`, `cat-file`, `merge-base`) are allowlisted individually; `--output`, `--filters`,
  `--textconv`, `-O` and friends are forbidden; `log` is never used (config can run gpg).
- Sensitive-path blobs are never read. Secret-bearing blobs are recorded as excluded with no hash and no text.
- Symlinks (mode 120000) and submodules (160000) are recorded and never read.
- Object ids are validated (40 or 64 hex); parent count and per-commit change count are capped (`truncated` flag).


## As built (supersedes the above where they differ; see docs/history.md)
- Schema is migration v4 (v3 is the graph). Added `git_commits.published`, `history_checkpoints.branch_label`, delta kind `signature_changed`.
- The dirty overlay is computed by content against HEAD blobs read with `cat-file`; git change detection is not used (it runs attribute filters). Overlay is recomputed on a no-op refresh.
- The lineage event and commit visibility are written in the publication transaction; unpublished runs are invisible.
