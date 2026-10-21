# Roadmap and acceptance

## Phases
- **v0.1** Foundation (CLI, SQLite schema, identities, security boundaries) → Code Intelligence (deterministic file-level indexing, symbols, edges) → Retrieval (FTS5, context governor, read-only stdio MCP) → Validation (privacy, consistency, portability, agent integration). Commands: `engbrain init | index | context | verify | mcp | agents`.
- **v0.2** Memory: decisions, bugs, bi-temporal facts, staleness, handoffs.
- **v0.3** Stage B dependency invalidation, impact analysis, test mapping and selection, evidence.
- **v0.4** Automated extraction, graph-enhanced search, learning from failures.

Out of v0.1: temporal extraction, embeddings, behavior graphs, intelligent regression selection, org-hosted server, Graphiti/GitNexus integration, Docker/Neo4j/cloud DB.

**v0.1 is not production-ready until a completed acceptance-test report (T1–T21 + benchmarks, see acceptance.md) exists.**

## Acceptance tests
T1 initial vs incremental index equivalent · T2 unchanged files not reprocessed · T3 branch/worktree isolation · T4 dirty tree represented · T5 interrupted index never exposes partial state · T6 MCP never reads excluded/unauthorized files · T7 offline run makes zero outbound requests · T8 sandbox-offline fails closed when unavailable · T9 token budgets and freshness metadata honored · T10 onboarding never overwrites config; each agent launches the MCP server and gets a bounded response · T11 malicious source cannot trigger unauthorized tool execution · T12 secret fixtures/derived content never retrieved · T13 deleting the index leaves the repo intact · T14 all fixtures synthetic and redistributable.

## Amendment traceability (reviewer's 12 changes)
| # | Change | Doc |
|---|---|---|
| 1 | Node/SQLite baseline | distribution.md |
| 2 | Generation = unit of consistency | ontology-and-schema.md, incremental-indexing.md |
| 3 | Worktree vs branch identity | ontology-and-schema.md |
| 4 | Two-stage incremental | incremental-indexing.md |
| 5 | Trust/proof classes | ontology-and-schema.md |
| 6 | Agent onboarding | mcp-spec.md |
| 7 | Context-budget governor | context-budget.md |
| 8 | Three permission tiers | architecture.md, security.md |
| 9 | Privacy guarantees separated | security.md, threat-model.md |
| 10 | MCP hardening, stdio only | mcp-spec.md, threat-model.md |
| 11 | Supply chain | distribution.md |
| 12 | v0.1 verify scope | verification-model.md |
| perf | Performance budget | benchmarks.md |

## Decisions recorded (conditional Phase 1A approval, 2026-10-21)
1. Windows: strict-offline index/context/mcp fully supported; `verify --run` fails closed with explanation; discovery stays available.
2. Tree-sitter is the baseline engine; SCIP stays **optional** per adapter until version compatibility, dependency availability, offline operation, memory use and indexing behavior are verified (scip-typescript needs Node >=22.13).
3. Project `engineering-brain`; CLI `engbrain` (provisional, pending npm/GitHub/trademark clearance).
4. Node baseline resolved to 22 LTS (>=22.13) + 24; see distribution.md. Parser spike done: WASM chosen.
5. Phase 1B remains blocked. See `design-review.md` (final amendment review) for resolved findings, accepted risks and the conditional go/no-go.
6. Parser decision: WASM `web-tree-sitter` 0.25.x with official grammars (spike S1). Schema decision: content-addressed facts + generation manifests (spike S2).
