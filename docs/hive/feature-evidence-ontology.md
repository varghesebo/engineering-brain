# Feature and evidence ontology (delta for Waves 2-4)

Kept separate dimensions (never collapsed): **extraction method** (`tree_sitter_syntax`, `import_resolver`, `route_pattern`,
`scip`, `test`, `human`, `model`), **relation certainty** (`resolved`, `ambiguous`, `unresolved`), **claim trust**
(`candidate`, `approved`, `retired`), **verification outcome** (`passed`, `failed`, `skipped`, `timed_out`, `incomplete`, `not_run`).

## Wave 1a facts
`symbols(kind, name, qualified_name, lines, signature_fingerprint, exported)`; `syntax_refs(kind import|export_from|require|dynamic_import,
target_text, line)`. A non-literal `import(x)` has `target_text = NULL`: explicitly unknown.

## Wave 2 (planned)
`resolutions` (generation-scoped import-to-file edges, certainty `resolved|ambiguous|unresolved`), `routes` (pattern-detected
HTTP entry points, method + path literal, certainty), `feature_candidates` / `feature_edges` (role, target, evidence_ref,
validity). User-confirmed boundaries from `.engineering-brain/features/*.json` (strictly validated, untrusted input).
No dynamic-call-graph claims.

## Wave 3-4 (planned)
`knowledge_claims` (candidate/approved/retired, scope, validity, invalidation rule), `evidence_records` (outcome, source and
environment fingerprints, artifact ref), `agent_tasks` / `agent_handoffs`. Approval and promotion are never performed by engbrain, never triggered by repository text (commit subjects, README, comments), and require an explicit human act (`--by`, `--yes`) against live evidence. Approval identity is ASSERTED, not authenticated: a hostile local process that can run the CLI can claim any name (see docs/features.md).

## Staleness
Evidence/claim applicability = {source fingerprint of its dependency set, environment fingerprint}. A change to any member makes
it `stale` (never deleted). History is preserved.


## As built (Phase H2; see docs/features.md)
Schema is migration v5 (`fact_entities`, `feature_entities`, `feature_edges`, `feature_gaps`, `features`, `feature_members`, `feature_lineage`, `feature_claims`). Detection is a bounded lexical scan keyed by content class, linking is per generation, annotations are read-time only.
