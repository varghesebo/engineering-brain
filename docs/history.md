# Commit ledger and incremental refresh (Phase H1)

Raw Git history is stored separately from the working-tree index and from any enrichment. Git is the source of commit identity; content hashes plus extractor versions identify parsed facts; commit
metadata is untrusted description. The design notes in `docs/hive/commit-refresh-protocol.md` describe the intent; this file describes what was built and measured. Schema: migration v4.

## Commands
- `engbrain refresh`: ingest new reachable commits and publish the current working-tree state. Default `--history=none`: the first run records HEAD only (history **partial**); later runs ingest every new reachable commit.
- `engbrain refresh --history=backfill [--max-commits N] [--time-budget-ms N]`: additionally ingest older unseen commits, parents first, up to N per run (default 5,000); resumable; `history complete` only once nothing unseen is left in a non-shallow repository.
- `engbrain refresh --status`: checkpoint, ledger size, orphaned commits, recent runs and lineage events.
- `engbrain history --since <ref>|last-refresh [--limit N]` and core `changesSince(db, {since, limit})`: commits reachable from the published checkpoint and not from `since`, parents first, with per-parent changes and symbol deltas. Read-only, answered from the ledger alone (never consults git).
- `engbrain changes --commit <sha>`: the recorded changes of one ingested commit.
Nothing here is reachable through MCP, and MCP has no write route.

## What is recorded
`git_commits` (id, tree, times, availability `full | shallow_boundary | oversized`, sanitised subject), `commit_parents` (a parent may have no commit row: an explicit unknown ancestor), `commit_changes` (per PARENT for merges; `-1` for a root commit; adds, modifications,
deletions, renames with a similarity score, copies, type changes; blob ids and sha256 content hashes; exclusion reason), `commit_symbol_deltas` (`added`, `removed`, `signature_changed` for supported symbol identities; `candidate_rename_of` only when exactly one removed and one added symbol of the same kind share a signature fingerprint, otherwise nothing),
`blob_hashes` (git blob id to sha256 or exclusion reason), `refresh_runs`, `history_checkpoints`, `lineage_events`. A commit message is stored truncated to 200 characters with control and bidirectional characters removed and is labelled `untrusted: true` on every read; it is never used as evidence of why anything was done.

## Algorithm and guarantees
1. One writer lock covers the whole run. The plan uses graph relationships only (never timestamps): no checkpoint is a `baseline`; the checkpoint an ancestor of HEAD is an `advance` (`rev-list --topo-order --reverse --parents processed..HEAD`); otherwise the checkpoint is orphaned and the run is a `switch` (branch changed) or `rewrite`, with the merge base as fork (`unrelated` when there is none); a checkpoint object that no longer exists is `base_missing`; an unborn HEAD is `head_unborn`.
2. Commits are ingested in batches of 100 (parents first). A batch is ONE transaction that also marks its commits complete, so a killed run leaves whole batches only and a resumed run skips them. A blob already resolved (blob id to hash) is neither read nor re-parsed; facts are content-addressed and shared with the working-tree index (`blob + extractor version`).
3. Ledger rows carry a `published` flag. Commits, lineage events and runs of an unpublished, failed or killed run are NOT visible to readers: `changesSince`, `commitChanges` and `--status` count only published commits, and the lineage event is written in the publication transaction. A run still marked `running` after a kill is marked `failed` by the next refresh (it holds the writer lock). The current working-tree generation is then built by the existing indexer, and in the SAME transaction that makes it current the history checkpoint advances. Readers therefore see the previous checkpoint until the whole run is published; ledger rows ingested by an unpublished or failed run are not reachable from the old checkpoint, so `changesSince` cannot return them.
4. The checkpoint only claims what was ingested: if a commit or time budget stops new-commit ingestion early, the checkpoint moves to the last commit of a parents-first prefix, not to HEAD, and the run reports `stopReason` and `remaining`. Cancellation (SIGINT or an abort signal) abandons the run without publishing.
5. After a rebase or force-push the old commits stay in the ledger as evidence (`orphaned` in `--status`) but are never returned by `changesSince`; `since` on an orphaned commit reports relation `rewritten`.
6. Dirty state is a separate observation: `overlay_hash` is computed exactly by content (every indexed file's sha256 against the sha256 of HEAD's blob for that path, plus untracked and deleted files). Uncommitted changes never get a commit id. Git's own change detection is NOT used because it runs attribute filters, which would execute repository-configured programs (found and fixed by the hostile-configuration test). Files the exclusion policy keeps out of the index are not part of the overlay.
7. GC keeps every fact still referenced by the ledger.

## Safety
New allowlisted git subcommands: `diff-tree`, `cat-file`, `merge-base`, `ls-tree` (with `rev-parse`, `ls-files`, `rev-list`, `symbolic-ref` from before). `log` is never used. Forbidden arguments now include `--filters`, `--output`, `-O`, `--open-files-in-pager`, `--no-index`. Replace refs are ignored (`--no-replace-objects`); a repository with `objects/info/alternates` is refused for history; a repository whose config sets `core.worktree` elsewhere is not treated as a git repository. Paths from git are NFC-normalised and checked; the exclusion policy and secret scanner apply to history exactly as to the working tree (sensitive-path, symlink and submodule blobs are never read; secret-bearing blobs are recorded with a reason and no hash or text). Per-commit parents (16) and changes (5,000) are capped and flagged.

## Measured (synthetic, macOS, Node 22.23.3 as darwin-x64)
300 commits over 200 files (3 files changed per commit): baseline (HEAD only) 1.4 s; backfill of the other 299 commits 28.0 s (11 commits/s, 1,094 file changes, 1,294 symbol deltas, 894 blobs read and parsed once each); a no-op refresh 0.34 s; a refresh with a dirty overlay 0.55 s; store 5.4 MiB; process peak RSS 145 MiB. Throughput is dominated by one `diff-tree` process per commit and parent; a batched diff is a candidate for H5. Not measured: large histories (100k+ commits), large commits, cold cache, other platforms.

## Review fixes (independent review, fresh Claude agent, not Codex)
No-op refresh no longer erases the overlay; symbol deltas are only computed when every existing side is known (no invented additions when a side is too large, secret or binary); unshallowing re-ingests boundary commits; unpublished state is invisible; paths git allows but a working tree does not are recorded with reason `unsafe_path` (colliding spellings flag the list incomplete); invisible Unicode (format, tag, zero-width characters) is stripped from subjects; oversized git output is classified and a commit too large to list is recorded as truncated; batches end early at 20,000 changes and a commit's changes are capped across all its parents; hashes are recorded only for read-eligible sides; `missing_object` verdicts are never cached; the overlay honours the configured size cap; the lineage branch comes from the last published checkpoint; git runs with `core.commitGraph=false`, `diff.renameLimit=1000`, `GIT_NO_LAZY_FETCH=1`.

## Known limitations
- `--history=backfill` ingests oldest unseen commits first; there is no "most recent N commits" horizon (the checkpoint stays closed under parents instead).
- Rename detection is git's (`-M`, default similarity); a file split or merge is not recognised. Symbol rename candidates need an identical signature fingerprint and are never asserted.
- Merge commits record one change list per parent; there is no combined-merge (conflict resolution) view.
- A shallow clone's boundary commits are recorded with unknown changes (not "everything added") and `history_partial`.
- `changesSince` builds the reachable set from the ledger before applying `limit`: cost grows with ledger size (to be measured and bounded in H5). `history_checkpoints.generation_id` is informational and can name a generation that GC later removed.
- A partial clone (promisor) repository errors instead of fetching (no lazy fetch is allowed).
- The overlay needs every HEAD blob once (cached afterwards): the first refresh of a large repository reads them all.
- Windows, Linux and Node 24 are untested; commands use fixed argument lists and `cat-file` (no shell), so they are expected to be portable but this is unverified.
