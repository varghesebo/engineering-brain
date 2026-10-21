# Foundation stage: deviations from the approved design

Each item states what the approved docs said, what the Foundation build does, and why. Nothing here weakens a
privacy or consistency invariant; items marked **stricter** are more conservative than the docs.

| # | Approved design | Foundation implementation | Reason |
|---|---|---|---|
| D1 | `dirty_fingerprint` over files differing from HEAD | `source_fingerprint` = hash of the **whole manifest** (path + content hash, or path + exclusion reason), computed from the database | Computing "differs from HEAD" correctly needs git blob comparison with attribute filters, which the hardened allowlist avoids. A whole-manifest hash is content-determined and strictly distinguishes any two source states. "Is this tree dirty?" is not answered yet. |
| D2 | Mismatched `history_key` refuses the store | Mismatch is **adopted and reported** (`historyChanged`), never refused; a null key is adopted silently once commits exist | Test finding: `git commit --amend` on a root commit changes the root-commit hash, so refusing locked users out of their own store. The store is already bound to this install and this real path, and facts are content-addressed. |
| D3 | `git status` / `diff` for dirtiness and freshness | Only `rev-parse`, `ls-files`, `rev-list`, `symbolic-ref` are allowed; file state comes from our own bounded reads and hashing | Spike S6: plain `git status` executed a hostile repo's `core.fsmonitor`. `status`/`diff` can also run attribute filters. Not needed for Foundation. |
| D4 | Symlinks: internal ones may be followed | **Stricter:** symlinks are never followed; recorded as `excluded_reason = symlink` | Simplest safe behaviour; avoids escape and TOCTOU questions. |
| D5 | v1 schema included symbols, syntax_refs, resolutions, evidence, tests | v1 has only `store_meta`, `generations`, `generation_extractors`, `generation_files`, `file_facts`; others arrive as later migrations | No tables built for later stages. `file_facts` gained `attrs_json` for the placeholder inventory extractor. |
| D6 | Foundation scope lists no extractor | A placeholder **inventory extractor** (language, byte size, line count) drives generations | Needed to exercise content-addressed reuse, T1/T2 and the publication path before real parsing exists. No symbols, no parsing. |
| D7 | Freshness levels (`hash_verified`, `heuristic`, ...) | Not implemented; `status` says so. The manifest already stores size, mtime_ns, ctime_ns, inode | Freshness belongs to the Code Intelligence stage per the approved sequence. T18 is therefore not covered. |
| D8 | Writer lock with heartbeat variants undecided | Exclusive-create lock; same-host stale detection by pid liveness; foreign-host locks expire only after 6 h | Long synchronous indexing cannot run a timer heartbeat. Known limit: pid reuse can make a dead owner look alive (fails safe by timing out). |
| D9 | Hardened git: `core.hooksPath=/dev/null` | **Corrected** to a private random scratch directory (empty hooks dir and empty config files) | `/dev/null` is Unix-only (review condition). Covered by tests that no `/dev/null` appears in arguments or environment. |
| D10 | n/a | Added: refuse a git work-tree root that has no `.git` entry (`core.worktree` redirect); refuse non-git roots that are a filesystem root or the home directory; refuse a store tracked by git; `uninstall --purge` refuses a tracked store dir | Found by self-review of hostile-repository behaviour. |
| D11 | Secret scanner described generically | Linear-time bounded patterns only; a first version with an unbounded scheme prefix stalled for over 45 s on a 1 MiB hostile file (found by self-review; regression tests added) | Scanner runs on every file of an untrusted repository. |
| D12 | Per-file parse timeout in a worker | **Not implemented** (there is no parser yet). Only a size cap (1 MiB default), binary/UTF-8 checks and linear-time scanning protect indexing | Belongs with real extractors. |
| D13 | `engbrain verify` discovery | Not implemented (commands context, verify, mcp, agents answer "not available in this build") | Later stages. |

## Not verified in this stage
- Windows and Linux: **no test was run on either.** Windows-specific code (no `O_NOFOLLOW`, reserved names, UNC detection, lock liveness via `process.kill(pid, 0)`, `core.hooksPath` with a Windows path) is written but unexercised. POSIX-only tests are marked `skipIf(win32)` and shell-script tests (T15) need a Windows equivalent.
- Node 24; cold-cache behaviour; filesystems other than the local APFS volume used here.
- Any OS isolation: none is implemented, so `repo-influenced-child` and `repo-test-execution` operations are refused.
