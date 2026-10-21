# Threat model

Assets: customer source, derived index/graph/memory, secrets, test evidence. Trust boundary: the machine/org network. Adversaries: malicious repo content, malicious dependency/MCP peer, curious or over-reaching agent, local other-user, supply-chain attacker.

| Threat | Vector | Mitigation | Test |
|---|---|---|---|
| Source exfiltration by our app | telemetry, crash reports, update checks, URLs in logs | no network code paths; no telemetry; logs contain ids not content | network-blocked run, zero connection attempts (T7) |
| Child-process egress | test runner or install script | sandbox + fail closed; self-test | T8 |
| Cloud-agent disclosure | hosted model receives context | documented, outside guarantee; org policy/allowlists; minimal context via budget governor | doc review |
| Secrets in index/context | `.env`, keys in source | exclude + scan; never store content of excluded files | T12 |
| Path traversal / symlink escape via MCP | crafted path args, symlink to `/etc` | canonicalize, root-confine, deny symlinks outside root | T6 |
| Cross-repo / cross-branch leakage | wrong generation served | per-worktree generation resolution, repository_id checks | T3 |
| Stale context presented as current | crash, branch switch | complete-generation-only reads, freshness metadata | T4, T5 |
| Prompt injection in source/comments/docs | text telling agent to run tools | label as untrusted data, no tool authority from content, output sanitization | T11 |
| Malicious MCP response consumed by us | external MCP peers | v0.1 consumes none; stdio server only | n/a |
| Excessive disclosure by query | broad query dumps repo | budget governor, pagination caps, per-call limits, audit log | T9 |
| Test execution abuse | repo scripts run code | explicit authorization, sandbox, scrubbed env | T8 |
| Concurrent writer corruption | two indexers | lock + generation promote | T5 |
| Supply chain | malicious dependency / install script | pins, lockfile, no remote install scripts, license/vuln scan, SBOM, provenance | CI |
| Hostile git config executes code (observed: `core.fsmonitor` ran on plain `git status`) | cloned repo's `.git/config` | hardened git flags, minimal env, sandbox where available | T15 |
| Install-time / dependency compromise | lifecycle scripts, native addons | minimal deps, `--ignore-scripts` CI-tested, pins, SBOM, provenance; see TCB table in security.md | T16 |
| Parser DoS / crash on hostile file | pathological source | size/time caps, worker with timeout, parse_status=error | T17 |
| False freshness | metadata-only check misses a content change | three freshness levels; heuristic never labelled verified | T18 |
| Local index tampering | other process edits DB | file perms 0600, integrity check, generation checksums | integrity test |

Out of scope for v0.1: remote transport, multi-user authz, hardware/OS compromise.
