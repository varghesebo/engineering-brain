# Phase H2 — evidence-based implementation report

- **State:** PASS (macOS / Node 22 only). The post-fix state was NOT re-reviewed by a fresh reviewer.
- **Repository / revision:** local branch `phase-2a`, base `2c9c8426a7e8ded302a26413ff563f7374ca2ee5`, everything since uncommitted. Nothing committed, pushed, merged or published.
- **Predecessor gate:** H1 (`H1-report.md`); source graph (2B) and ledger operational.
- **Scope:** deterministic feature/capability graph (migration v5): content-addressed entity detections, per-generation linking across files/packages/services, coverage gaps, discovered flow features, feature lineage, read-time annotations, candidate claims with human approval, bounded queries and CLI `feature ...`. Excluded: any model call, MCP exposure, YAML OpenAPI, call graphs, runtime verification.
- **Changed files (new):** `packages/core/src/features/{lexer,detectors,entityExtractor,featureBuilder,queries,annotations,claims}.ts`; migration v5; `EntityFact` + `FactWriter` + `defaultExtractors.ts` + `indexer.ts` hook; `packages/cli/src/commands/feature.ts`; tests `packages/core/test/featureDetectors.test.ts`, `tests/acceptance/{h2-features,h2-review}.test.ts`, `tests/helpers/feature-fixture.ts`; bench `tests/bench/feature-bench.mjs`; docs `docs/features.md`, `docs/hive/feature-evidence-ontology.md`.
- **Tests** (`npx tsc -b && npx tsc -p tsconfig.test.json --noEmit && npx vitest run`, Node 22.23.3): 38 files, **485 passed, 0 failed, 0 skipped**; log `evidence/h2-vitest-verbose.txt`.
  | Gate | Result |
  |---|---|
  | Five-service fixture: UI route -> API -> event -> consumer -> table with a test; missing consumer, dynamic route, dynamic URL and unmatched UI call reported as gaps | pass |
  | Editing a backend route updates relationships and records the rename; other branches isolated (graph, lineage and validity); incremental equals clean rebuild | pass |
  | Candidate statements cannot become verified by repetition, field smuggling, self-approval or stale evidence; documentation never creates entities; annotations strictly validated | pass |
  | Split / merge / rename / ambiguous identity reports | pass |
  | Bounded traversal on a 300-route hub; pathological sources bounded; truncation reported as gaps | pass |
  | Review regressions (19 findings; 16 integration + 8 detector tests) | pass |
  | Offline (network guard) for every feature command | pass |
- **Security/privacy:** nothing executes repository code or contacts a network; fact extraction is a bounded lexical scan; URL literals are stored without query strings or credentials; annotations live in the local store directory and are validated as untrusted; claim text is filtered for control and invisible characters; read paths use the read-only store handle.
- **Measured (synthetic):** 100 services x 200 routes: 602 files, 82,100 entities, 121,000 edges, 20,000 flows; initial index 9.8 s (feature build 6.3 s), one-file change 7.3 s, DB 155 MiB, peak RSS 493 MiB; list 5 ms, show 0.7 ms, trace 6.5 ms, impact on a 200-entity file 1.4 s. Details in `docs/features.md`.
- **Independent review:** fresh read-only Claude agent (NOT Codex; not a strict audit): 19 confirmed defects, all fixed with regression tests (listed in `docs/features.md`); plausible items handled: spec base paths, per-package spec judgement, comparator, gap-count query.
- **Known uncertainty:** (a) no re-review after fixes; (b) lexical detection (not parsing), limited to the listed adapters; (c) approval identity is asserted, not authenticated; (d) the feature graph is rebuilt in full per generation; (e) route and handler evidence staleness is file-granular; (f) lineage is heuristic; (g) macOS/Node 22 only.
- **Next phase:** H3 (temporal memory). **User approvals needed:** commit/push (none authorised).
