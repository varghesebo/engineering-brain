# Architecture

Apache-2.0, local-first, repo-agnostic. Engine code is generic; every customer's data lives only in a gitignored `.engineering-brain/` inside their repo (or an org-approved local dir).

```
PUBLIC REPO (this)                 CUSTOMER REPO
  packages/ core, graph-engine,      src/, tests/
  mcp-server, security, cli    -->   .engineering-brain/  (gitignored)
  language-adapters/                   index.db (SQLite, generations)
  tests/fixtures (synthetic only)      evidence/  memories/  audit.log
```

## Modules (independent)
1. Code graph — files, symbols, edges (v0.1)
2. Temporal memory — decisions, bugs, handoffs (v0.2)
3. Behavior/invariant mapping (v0.3+)
4. Change-impact analysis (v0.3)
5. Verification/regression intelligence (v0.3; v0.1 = discover + authorized run)
6. Evidence & learning (v0.2–0.4)

Deterministic analysis first. LLM inference optional and off by default. Storage: SQLite (`better-sqlite3`, FTS5). Git and current source are the source of truth; nothing cached overrides code.

## Privacy modes
- **Strict offline (default):** no network use by the application; test execution requires verified isolation or refuses (fail closed).
- **Org-hosted (later):** authenticated internal service, per-repo authorization.
- **Explicit cloud-agent:** user connects hosted Claude/Codex. We cannot guarantee source does not reach the provider; documented, not claimed.

## Permission tiers
| Tier | Operations | Allowed writes |
|---|---|---|
| Retrieve | MCP read tools | none |
| Index | `engbrain index` | private index storage only |
| Execute | `engbrain verify`, saving verified memories | explicit per-run authorization; may run untrusted repo code |

## Capability classification
| Capability | Class |
|---|---|
| TS/JS parsing | existing dependency (tree-sitter) |
| Cross-language symbols | thin adapter (SCIP) |
| SQLite + FTS5 | existing dependency |
| MCP server | existing dependency (official SDK), stdio |
| Generations, identity, locking, context governor, provenance model | custom |
| Sandboxed test execution | custom thin layer over OS facilities, per-OS |
| Temporal memory, impact analysis, test selection | deferred (v0.2/v0.3) |
| Embeddings, behavior graphs, org-hosted server | deferred / experimental |
