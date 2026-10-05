# Dependency and license decision

The historical Phase 0 contract had five direct third-party dependencies:

| Package | Version | Purpose | License | Decision |
|---|---:|---|---|---|
| `clap` | 4.6.3 | Parse the two skeleton CLI commands | MIT OR Apache-2.0 | Accepted |
| `rusqlite` | 0.39.0 | Synchronous SQLite migrations with bundled SQLite | MIT | Accepted |
| `serde` | 1.0.229 | Typed contract and fixture serialization | MIT OR Apache-2.0 | Accepted |
| `serde_json` | 1.0.151 | JSON schemas, examples, fixtures, and CLI output | MIT OR Apache-2.0 | Accepted |
| `sha2` | 0.10.9 | SHA-256 verification for migrations, fixture bodies, and dependency evidence | MIT OR Apache-2.0 | Accepted |

`Cargo.lock` is committed. `licenses/dependency-inventory.json` contains every
resolved workspace and registry package, including target-specific packages.
The inventory records the `Cargo.lock` SHA-256. The test suite checks exact
name/version coverage between that inventory and the lockfile and refuses
missing, blank, unknown, or AGPL license declarations.

The reviewed inventory records `firecrawl_source_copied=false` and
`agpl_code_present=false`; no locked dependency declares AGPL. This proof is a
dependency and repository review claim, not a general provenance theorem.

## Security scan, 2026.10.05

Rustls is locked at 0.23.45 to address [RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285.html).
The lock update also changes its cryptography and certificate-validation dependencies.
The license inventory covers the resulting lockfile.

The PDF extraction chain includes `ttf-parser` 0.25.1 through `lopdf` and `pdf-extract`.
[RUSTSEC-2026-0192](https://rustsec.org/advisories/RUSTSEC-2026-0192.html) marks that parser as unmaintained.
The advisory provides no patched version.
Replacing the PDF parser requires a separate compatibility review.

An OSV query checked all 305 locked crates.io package versions after the update.
It returned the font-parser maintenance advisory and no other matching advisory.
This result describes that scan, not a guarantee against undisclosed defects.

The [saved scan receipt](docs/security-scan-2026.10.05.json) records the lock hash and API response.
