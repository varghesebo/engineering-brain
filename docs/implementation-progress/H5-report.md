# Phase H5 report (PARTIAL, gate NOT passed)

Status: **CLOSED AS DOCUMENTED PARTIAL on the user's instruction ("fix and move on to rest")**; NOT a full gate pass. Deferred: feature-graph reuse, symbol-search index, resource caps, Windows/Linux/Node 24 runs, agent-baseline benchmark, federation ADR. Only the locally measurable part was run. Nothing committed or pushed.

## Measured (synthetic 50,000-file TypeScript repo; macOS, Node 22.23.3 as darwin-x64, single process; `evidence/h5-index-bench-50k.txt`)
| Metric | Result |
|---|---|
| Initial index | 126 s (397 files/s), 757k symbols, 607k graph edges, DB 913 MiB, peak RSS 897 MiB (process peak 1,265 MiB) |
| Unchanged re-index | 7.0 s, 0 parses |
| One-file change | **48.8 s**, 1 file parsed, 50,050 facts reused, but the module/symbol/package graph is rebuilt in full (~40 s) |
| Freshness | heuristic 0.55 s; hash_verified 4.3 s |
| Symbol search p95 | 272 ms (linear substring scan, no FTS) |
| Graph queries | dependencies/dependents depth 3: 5-18 ms; impact ~200 ms (truncated by node/edge budget); validate 2.0 s; stats 2.2 s |
| Context packet | 1 call, 0.87 s p50, 1,270 tokens, first file correct; naive baseline scanned 50,051 files (~16.4M tokens if read) |

## Update: incremental graph reuse (implemented, locally verified)
Unchanged files' graph edges are now carried over from the previous generation when nothing that could affect them changed (same resolver/extractors, identical path set, only code files modified, each modified file keeps its exported/imported surface). Anything else is a full rebuild. Result is identical to a clean build including edge ids (`tests/acceptance/h5-incremental-graph.test.ts`; the existing 10-seed clean-vs-incremental suite still passes). 50k files (`evidence/h5-index-bench-50k-after.txt`): body-only one-file edit **21 s (was ~49 s)**; an edit that adds an export still triggers a full rebuild (~52 s). Remaining cost of the fast path: loading all facts (~3.4 s), package aggregation/renumbering (~6.9 s) and ~10 s elsewhere (features, validation); not yet optimised.

Independent review of the reuse change (fresh read-only Claude agent; NOT Codex): no confirmed counterexample. Its plausible concerns were addressed (RESOLVER_VERSION bumped 2 -> 3 so older graphs are never carried forward; test helper filter fixed; added a chained two-generation reuse test with package-edge counts). The post-fix state was not re-reviewed.

## Negative findings against the H5 acceptance criteria
- Single-file updates: parsing is incremental; graph construction is now incremental only for edits that keep a file's surface (21 s at 50k); surface-changing edits still rebuild the whole graph (~52 s). The feature graph is still rebuilt in full.
- Symbol search is linear (266 ms p95); FTS/adjacency indexing not yet added.
- Memory use is within the measured budget but no configurable cap exists.

## NOT done (blocked or not started)
- Windows and Linux runs and Node 24: no such runners exist here. Portability stays "macOS/Node 22 only".
- History stress fixture with merges/rebases at 50k scale, worker queues/backpressure, cache pruning, vacuum.
- Benchmark against a Claude Code / Codex baseline (no Codex, no network); effect size with uncertainty is therefore NOT available.
- Federation ADR; optional multi-language adapter.
- Independent review of H5 changes (none made yet).

## Needed to proceed
Either approve continuing with local-only optimisation (incremental graph rebuild, FTS, caps) and record the rest as blocked, or provide Linux/Windows runners and a baseline agent setup. Sentinel 3A-3E must not start until H5 is resolved.
