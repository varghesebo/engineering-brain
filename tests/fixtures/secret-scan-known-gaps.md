# Secret scanner: tracked false negatives

The scanner (`packages/core/src/secretScan.ts`) uses fixed patterns plus an entropy check. It cannot find every
secret. These categories are **known to be missed** and are pinned by tests in
`packages/core/test/secretScan.test.ts` so the limitation stays visible:

- short passwords/tokens (under the assignment pattern's 12-character minimum)
- secrets built by string concatenation or split across lines
- low-entropy long tokens
- secrets in formats with no recognised prefix or key name
- secrets inside files excluded as binary or oversized (those are excluded from indexing instead)

Mitigations: only identifiers/signatures will be stored in later stages (never literal values); sensitive file
names are excluded without reading; false positives are accepted on the safe side. Do not claim secrets cannot
appear in the index.
