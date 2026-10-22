# Sentinel 3D report: adversarial assurance (import-based, non-executing)

Status: **IMPLEMENTED FOR IMPORTED RESULTS ONLY; gate not met.** No fuzzer, mutation tool, property runner, race detector or solver is executed here. Results enter only as signed or operator-accepted evidence imports (quarantine otherwise) bound to the exact revision. Independent review: fresh Claude agents (accepted by the user; not Codex). Built by several parallel Claude agents with file ownership; integrated and re-tested together.

## Built
- Schema v11 (evidence-import formats widened by SQLite's documented table rebuild; adapters, target allowlist, invariants, hypotheses, mutation runs/mutants with `claims_proof = 0`, formal results with `scope = 'model_only'` and `claims_application_proof = 0`, reproductions, quotas, stored assurance detail).
- Parsers (`evidence/assuranceParsers.ts`): Stryker, fast-check, Hypothesis (wrapper), Semgrep JSON, TLA+/Z3 (wrapper), race logs; sanitised, size-bounded, partial on doubt.
- Registry (`sentinel/assurance/{adapters,hypotheses,invariants,quotas}.ts`): unsupported/unregistered techniques stay visible; isolation must be verified and network is never allowed; targets must be allowlisted fixtures/local processes (no URLs/IPs/absolute paths); approved invariants are immutable (supersede only) and never approved by the builder; quotas fail closed and only ever get consumed.
- Results (`sentinel/assurance/{mutation,formal,repro,assuranceChecks}.ts`, `campaigns.ts`): survivors fail mutation_tests, 100% is "not proof"; formal success counts only with recorded assumptions and as model-only; missing tools are recorded `not_run`/unsupported and keep their pass INCOMPLETE; reproductions with seeds/minimized inputs; memory candidates created as candidates only.

## Limits
Signing proves provenance, not truth: a fabricated report signed with a valid key would be accepted. Fixtures prove plumbing, verdict mapping and fail-closed policy, not that tools find real bugs. Wrapper formats (fast-check, Hypothesis, TLA+, Z3, race logs) are conventions of this tool. Absolute paths in assurance artifacts are dropped, not mapped to the repository. No CLI commands for 3D yet (library API only).

## Verification
Full suite after integrating all parallel-agent work and fixes: **52 files, 670 tests passed, 0 failed**, typecheck clean, Node 22.23.3, macOS (`evidence/s3cde-vitest-verbose.txt`). An earlier run had one failure: the Foundation concurrency test T19 timed out under parallel load (42 s alone); its timeout was raised with a comment, then the suite was re-run.
