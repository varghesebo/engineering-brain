# Dependency and structure graph (Phase 2B)

A generation-scoped, deterministic graph over the Phase 2A facts. It answers "what does this import / extend / reference" and "what could be
structurally affected if I change this". It is **syntactic and static**: no type information, no call graph, no runtime behaviour.

## Edges (`graph_edges`, one set per generation, immutable once published)
| Family | Kinds | From -> to |
|---|---|---|
| module | `IMPORTS`, `RE_EXPORTS` | file -> file / external package / unknown |
| symbol | `IMPORTS` (binding), `REFERENCES`, `EXTENDS`, `IMPLEMENTS` | file or symbol -> symbol / file / unknown |
| package | `DEPENDS_ON` | workspace package -> package / external package (aggregated, with a count) |

Every edge carries `mechanism` (`tree_sitter_syntax`), `resolution` and a machine-readable `reason`, the extractor id (`graph:<RESOLVER_VERSION>`) and a line.
Resolution is one of `resolved | external | unresolved | ambiguous | dynamic | syntactic_only`. `REFERENCES` is always `syntactic_only`: it records that a name
bound by an import appears in a symbol's body, nothing more. `CALLS` is never produced. `CONTAINS`/`DEFINES`/`EXPORTS` are not stored; read structure with
`engbrain symbols` / `engbrain imports`. The CLI rejects those kinds with an explicit message instead of returning nothing.

## How targets are decided
- Binding resolution follows re-export chains (`export { x } from`, `export * from`, named barrels) with the ES `ResolveExport` rule: one resolve set per lookup (each module/name pair
  explored once, so diamonds of `export *` cost O(edges), not O(paths)), a depth bound of 16, and per-generation memoisation of complete lookups.
- An `export *` branch that is external, unresolved or dynamic could supply the name, so a name not found elsewhere is `unresolved` (`star_reexport_undecidable`); found elsewhere it is
  `ambiguous`. It is never reported `resolved` on partial knowledge.
- A reference or heritage name that an enclosing function, block, loop head or catch clause declares (parameters, `let/const/var`, function/class declarations, `for..of/in` variables,
  catch bindings, named function expressions) is a local binding, not the import of the same name. Heritage of such a name has an unknown target. Limits: `var` declared in a nested block of
  a function is not treated as hoisted; `with`/`eval` are not modelled.
- Ambiguity is only reported between different module families; see `docs/code-intelligence.md` for resolver rules.

## Queries (`engbrain graph ...`, `@engbrain/core` `graph.ts`)
`dependencies`, `dependents` (bounded BFS), `path` (shortest path over decided edges only: `unresolved/ambiguous/dynamic/syntactic_only` edges never form a path),
`cycles` (iterative Tarjan over resolved file imports), `impact`, `references`, `stats`, `validate`. Nodes: `--file`, `--symbol path#Qualified.name` (or `path#key:<symbolKey>`; the
last `#` separates, so paths containing `#` work), `--package`, `--external`. Modes `module | symbol | all`; `--kinds` filters.

`impact` reports POTENTIAL STRUCTURAL effects: files and symbols that import, re-export, reference by name, extend or implement the target, followed through importing files
(and through `DEPENDS_ON` for a package target). The result also lists counts of dynamic/unresolved/ambiguous edges in the generation and possibly related unresolved specifiers: they may hide dependents.
Depth, node, edge and wall-clock budgets apply to the whole traversal; the result says which one truncated it. A truncated result is not "all dependents".

All reads run in one WAL snapshot of the current generation. Hot lookups name their index (`INDEXED BY`): with `ORDER BY edge_id LIMIT` the planner otherwise scans the whole table.

## Freshness
Same levels as the index (`hash_verified | heuristic | stale | unknown`). The graph is rebuilt in full for every generation, so it is as fresh as the generation; `indexerChanged` is reported when extractor
or resolver versions differ.

## Measured (synthetic TypeScript repositories, macOS, Node 22.23.3 as darwin-x64, single process)
The synthetic repo now has per-directory barrels (`export *`), imports through them, name references and `extends` between files (about 12 edges/file). Reproduce: `node tests/bench/index-bench.mjs <files> <dir>`.

| Files | Initial index | Graph edges | One-file change | Graph build (one-file) | impact (file) | dependents d3 | validate | Peak RSS |
|---|---|---|---|---|---|---|---|---|
| 100 | 0.50 s | 1,199 | 135 ms | 31 ms | 2 ms | 0.5 ms | 3 ms | 147 MiB |
| 2,000 | 2.76 s | 24,270 | 1.17 s | 0.8 s | 9 ms | 2 ms | 58 ms | 241 MiB |
| 20,000 | 36.2 s | 242,842 | 13.8 s | 10.9 s | 92 ms | 20 ms | 745 ms | 767 MiB |

At 20,000 files the 20k run holds about 243k edges and 303k symbols; the DB is 399 MiB. Not measured: cold cache, real-world code, repositories over 20,000 files, other platforms.

## Known limitations
- **Edges are recomputed per generation.** A one-file change re-parses one file but rebuilds the whole graph (about 11 s at 20k files). Incremental edge reuse is deferred (H5).
- Memory at 20k files peaks near 770 MiB in the benchmark process; 100k files is untested and would be several times that.
- Syntactic only: no type-directed resolution, no `node_modules` lookup, no `exports` conditions, no call graph, no JSX component usage, no dynamic `require(x)`.
- `REFERENCES` matches by name within one file's import bindings; it can miss references (properties, re-assignments) and, outside the modelled scopes, include shadowed names.
- Platforms: macOS/Node 22 only; Linux, Windows and Node 24 untested.
