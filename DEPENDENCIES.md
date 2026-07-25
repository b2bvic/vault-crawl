# Dependency and license decision

Phase 0 has five direct third-party dependencies:

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
