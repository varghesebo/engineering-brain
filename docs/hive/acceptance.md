# Hive acceptance specifications

Conventions as `docs/acceptance.md`: synthetic fixtures only, per-OS reporting, skipped-with-reason never counted as passed.
Foundation tests T1-T22 must stay green.

## Wave 1a (syntax extractor)
- H1a-1 declarations/imports extracted for function, class, method, interface, type alias, enum, const arrow/function; exported flag correct.
- H1a-2 `require("x")` and `import("x")` literals recorded; `import(expr)` recorded with NULL target (unknown).
- H1a-3 syntax errors yield `parse_status=error` with partial facts, never a crash; hostile inputs (deep nesting, 1 MiB minified line, binary-looking text) bounded in time.
- H1a-4 extractor output is deterministic; unchanged blob + extractor version is not re-extracted.

## Wave 1 (commit ledger and refresh) - maps to blueprint tests 1-8, 15, 16
- H1-1 **Commit fidelity**: A..E history with a merge; ledger has every commit once, correct parents, per-parent changes, no duplicate facts.
- H1-2 **Rebase / force-push**: lineage `rewrite` with correct fork; orphaned commits excluded from `changesSince`; identical blobs not re-extracted.
- H1-3 **History gaps**: shallow clone -> `history_partial`, `shallow_boundary` commits, no invented commits; missing checkpoint object -> `base_missing`.
- H1-4 **Blob reuse**: unchanged blob + extractor version is not read or re-extracted across commits and branches (counters asserted).
- H1-5 **Incremental equivalence**: stepwise `refresh` over A..E equals a one-shot backfill for ledger rows, and the published generation equals a clean index of the same source state.
- H1-6 **Atomic reader safety**: injected faults and SIGKILL at each ingest/publish point leave readers on the previous checkpoint; resume completes; result equals the uninterrupted run.
- H1-7 **Worktree isolation**: two dirty overlays on the same HEAD stay separate; overlay hash empty when clean.
- H1-8 **Rename accuracy**: file renames carry a score; a renamed symbol is only ever a `candidate_rename_of`, and ambiguous cases produce none.
- H1-9 **Exclusions**: committed `.env`/secret blobs are never read or stored; symlinks and submodules recorded, not followed.
- H1-10 **Repository config attacks**: hostile `diff.external`, `diff.*.textconv`, filters, `core.fsmonitor`, hooks, `log.showSignature`/`gpg.program`, `core.worktree`, replace refs and alternates execute nothing and read nothing outside the root.
- H1-11 **Memory poisoning**: commit subjects containing instructions are stored as untrusted text and change no state.
- H1-12 **Offline**: refresh under the network guard makes zero attempts (static import check extended to new modules).
- H1-13 **Branch correctness**: after a branch switch, `changesSince` returns only commits reachable from the current HEAD.

Resource measurements (reported, not gated): ingest throughput (commits/s), blob reads, peak RSS, DB growth on a synthetic 300-commit history.

## Waves 2-5
Defined at the start of each wave in `rollout.md`; each wave adds its own section here.
