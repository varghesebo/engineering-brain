# Sentinel 3E report: enterprise assurance (local slice)

Status: **LOCAL SLICE IMPLEMENTED; gate NOT met.** 3E requires 3A-3D to be real (executing) and independently reviewed; here they are non-executing and reviewed by Claude agents (accepted by the user, not Codex). Nothing releases, merges, pushes or deploys.

## Built (schema v12, `sentinel/enterprise/`)
Release manifests (canonical JSON, sha256, HMAC; stale on any source/environment/policy/evidence change); Ed25519 verifier public keys (private keys refused, no self-registration, revocable); principal grants (approver, second approver, exception approver, auditor, exporter; scope-bound; revocable); exceptions (only for policy-added extra checks; never mandatory checks; separate approver; an excepted check is APPROVAL_REQUIRED, never passed); hash-chained controller decisions (worst-outcome ordering; ELIGIBLE grants no authority; A3/A4 need a valid verifier signature over the manifest); incident-regression reviews; audited, classification-redacted exports; an assurance report with fixed NOT CERTIFIED / NOT FORMALLY PROVED / NOT EXECUTED / UNSUPPORTED PLATFORMS / reviewer-was-a-Claude-agent sections.

## Needs the user
1. Verifier identity: principal names and Ed25519 public keys you generate (private keys never shared), and who registers them.
2. At least two real approvers plus an exception approver (none may be the builder) and their scopes.
3. Explicit release approval for any real release/merge decision.
4. A decision on data retention/purge (append-only tables cannot be purged without a design such as crypto-shredding).

## Limits
The decision chain has no MAC (a correctly extended raw insert is undetectable); incident reviews are not fingerprint-bound; the task layer can count an approval without a grant (only `decide()` refuses it); no supply-chain (SPDX/CycloneDX/in-toto/SLSA) parsers; no CLI for 3E yet; Linux/Windows/Node 24 untested.

## Verification
Full suite after integrating all parallel-agent work and fixes: **52 files, 670 tests passed, 0 failed**, typecheck clean, Node 22.23.3, macOS (`evidence/s3cde-vitest-verbose.txt`). An earlier run had one failure: the Foundation concurrency test T19 timed out under parallel load (42 s alone); its timeout was raised with a comment, then the suite was re-run.
