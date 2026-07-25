# vault-crawl

`vault-crawl` is a Rust-first, host-local retrieval and corpus core. The public
workspace provides bounded static HTTP retrieval, extraction, provenance,
content-addressed storage, SQLite search, offline fixtures, and read-only
operator diagnostics.

Part of a larger system: this repository proves **P06 (evidence outranks
fluency)** and **P10 (production means persistence, bounded autonomy, and
observability)** from the [Seventeen
Principles](https://victorvalentineromo.com/principles). Everything it stores
carries provenance; everything it claims about its own state comes from
`status` and `doctor` commands that fail closed rather than guess.

Project boundaries are caller-defined. Pass any validated lower-case project ID
with `--project`; no personal or organization-specific domain list is compiled
into the core. `config/projects.example.json` demonstrates a generic 3+1 layout
and is marked as an example rather than a runtime default.

The public core does not include private workflow intake, outbound delivery
consumers, schedulers, service definitions, daemon listeners, browser
automation, or external-write capabilities.

## Worked example

Initialize a project, ingest the offline fixture corpus, and ask the store what
it actually holds:

```sh
cargo run -p vault-crawl-cli -- --project example status --json
cargo run -p vault-crawl-fixtures --bin vault-crawl-fixture-server &
cargo run -p vault-crawl-cli -- --project example doctor --json
```

`doctor` reports schema version, migration checksums, blob-store integrity, and
throttle state as observed facts. If a check cannot run, it reports that it
could not run. It never reports health it did not verify (P06).

## Verify

```sh
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all
cargo run -p vault-crawl-cli -- --project example status --json
cargo run -p vault-crawl-cli -- --project example doctor --json
```

The fixture server is local-only and rejects non-loopback bind addresses:

```sh
cargo run -p vault-crawl-fixtures --bin vault-crawl-fixture-server -- --help
```

## Safety state

- Static fetches pin an approved address and re-check redirects and peers.
- Downloaded material remains untrusted evidence.
- State, blobs, logs, and receipts are isolated by validated project ID.
- Capability examples are default deny and inactive.
- Imported registry records default inactive.
- Fixture content is locally authored and deterministic.
- Firecrawl source was not copied.

## How this was built

Specification and judgment: human. The contract this workspace implements, the
fail-closed posture, and the decision of what stays out of the public core were
written down before any code existed. Implementation: AI models executing that
specification, verified through deterministic formatting, linting, schema,
migration, and test checks, plus an adversarial audit before publish. The
fixture corpus is locally authored; no scraped third-party content ships here.
