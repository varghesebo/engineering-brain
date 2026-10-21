# Incremental indexing and freshness

Schema and publication rules: see `ontology-and-schema.md`.

## Stage A (v0.1): file-level, deterministic
1. Enumerate files via **hardened git** (`ls-files` + untracked) or a filesystem walk for non-git dirs; apply exclusions (secrets, generated, logs, binaries, symlinks escaping the root, files over a size cap).
2. For each file compute content hash (SHA-256). Skip re-hashing only when the explicit "metadata trust" fast path applies (see Freshness) and the user did not request a verified run.
3. New hash => parse with the extractor (in-process WASM tree-sitter) and write `file_facts`. Known hash+extractor version => reuse, zero parse. Deleted/renamed paths simply change the manifest.
4. Write the manifest, derive import resolutions, validate, publish (single transaction).
Properties: initial and incremental indexing of the same tree yield identical manifests and facts (T1); unchanged files are not re-parsed (T2).

## Stage B (after Stage A correctness tests): dependency invalidation
Symbol/edge-level invalidation, feature maps, test relations. Not in v0.1.

## Git handling (security-relevant)
Foundation allows only `rev-parse`, `ls-files`, `rev-list`, `symbolic-ref` (no `status`/`diff`, see deviation D3). Every git call uses hardened options: `-c core.fsmonitor=false -c core.hooksPath=/dev/null --no-optional-locks`, `GIT_CONFIG_NOSYSTEM=1`, global config disabled, minimal environment, timeout, and no network-capable subcommands. Spike S6 showed plain `git status` executing a hostile repo's `core.fsmonitor`. Other command-executing config keys are not yet audited (open item). No git operation may write refs, index or config.

## Freshness: three evidence levels, never conflated
| Level | Meaning | How established | Cost (20k files, warm) |
|---|---|---|---|
| `hash_verified` | every non-excluded file's current content hash equals the manifest and the revision/dirty set matches | full re-hash during `engbrain index`, `engbrain status --verify`, or an explicit `check_freshness` | ~1 s (cold cache unmeasured) |
| `heuristic` | hardened `git status` + stat tuple (size, mtime, **ctime**, inode) match the manifest metadata, and/or no watcher events since the last hash-verified check | cheap check on retrieval | ~100–200 ms |
| `stale` | a difference was detected | any mismatch; response lists up to N changed paths | — |
| `unknown` | cannot decide (git unavailable, watcher dead, check timed out, unsupported filesystem) | — | — |
Rules: heuristic is **never** labelled verified. Metadata can miss content changes (size+mtime restore); in spike S3 git caught it via ctime, but that is unproven on all OS/filesystems. Every response states `freshness`, `basis`, `last_hash_verified_at`, and generation id.

## Read consistency and races
- Each MCP call resolves `current_generation_id` and runs all its reads inside one read transaction (WAL snapshot): internally consistent.
- A file can change between the freshness check and the agent's use. Responses carry per-file `content_hash`; the read-only `check_freshness(paths[])` tool re-hashes up to N named files so an agent can confirm just before relying on or editing them. This narrows, not eliminates, the race; agents' own edit tools remain the final authority and current source always wins.

## Concurrency
One writer: exclusive-create lock file (owner pid, host, start time) + stale-lock detection + timeout; works on Windows. Readers are unaffected by the writer. Interrupted run: `building` generations become `abandoned` at next start. Integrity check command; forward-only migrations with pre-migration backup.
Storage must be on a **local filesystem** (WAL needs shared memory). `engbrain init` detects common network/remote mounts where possible and refuses with a clear error; detection is best-effort and documented as such.

## Edge cases (tests)
Renames, deletions, case-only renames, Unicode NFC/NFD names, symlinks (internal/escaping), rebase, cherry-pick, detached HEAD, deleted branch, simultaneous worktrees, dirty trees, shallow clone, repo with no commits, non-git dir, copied/moved store, crash at each publication step.

## Triggers
Manual `engbrain index`; optional async debounced watcher (non-blocking); periodic reconciliation. No CPU-heavy idle work.
