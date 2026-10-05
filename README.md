# Rust retrieval core with provenance: vault-crawl

vault-crawl retrieves static web content and stores provenance for operators preparing records for hosted-model workflows.
It keeps source material and retrieval receipts in a corpus you can inspect and move.

[Project page](https://scalewithsearch.com/code/vault-crawl)

## Install

Requirements: Git, Bash, and Rust 1.94 or later on a Unix system.
The workspace uses bundled SQLite and a committed Cargo lockfile.

```sh
git clone https://github.com/b2bvic/vault-crawl.git
cd vault-crawl
cargo build --locked -p vault-crawl-cli
```

## Quick start

Parse the shipped HTML fixture without making a network request:

```sh
bash examples/demo.sh
```

The isolated demo prints extracted content, hashes, artifact paths, and `network_requests: 0`.
Its temporary state is removed when the demo exits.
For a retained JSON export, run:

```sh
cargo run --locked -p vault-crawl-cli -- --project example \
  parse fixtures/http/article.html \
  --source-url https://example.com/article --content-type text/html \
  --json > extraction.json
```

This command preserves state under the default project directory and writes `extraction.json` in the current directory.
`parse` creates an artifact; it does not add a searchable document to the fetched corpus.

## How it works

The Rust workspace supplies owned agent retrieval storage through four crates:

- `vault-crawl-core`: static retrieval, extraction, migrations, storage, and policy checks.
- `vault-crawl-cli`: foreground fetch, scrape, parse, batch, feed, query, status, doctor, and receipt commands.
- `vault-crawl-fixtures`: deterministic loopback fixtures for tests.
- `vault-crawl-adapters`: generic registry records without a source-specific API client.

SHA-256 addresses identify stored blobs.
SQLite corpus search uses FTS5 and supports caller, project, adapter, and host filters.
Content-addressed agent records retain source hashes and provenance.
Public HTTP retrieval checks destinations, redirects, robots rules, and budgets.
See [the architecture](docs/architecture.md) for the trust boundary.

Before running `doctor` on retained data, back up its state and receipt directories.
`doctor` opens or migrates the store and runs recovery.
It can remove temporary files or quarantine orphaned blobs.

```sh
cargo run --locked -p vault-crawl-cli -- --project example status --json
cargo run --locked -p vault-crawl-cli -- --project example doctor --json
```

These diagnostics report capabilities, repository contracts, and the selected store's observed integrity checks.
They do not prove that every retained project corpus is healthy.

## Portability

The corpus uses SQLite, content-addressed byte files, JSON artifacts, and JSON receipts.
Default state resides at `~/.local/share/vault-crawl/<project>/`.
Default receipts reside at `~/.local/state/vault-crawl/receipts/<project>/`.
`--state-root` and `--receipt-root` select explicit export and storage locations.

The CLI can emit extracted Markdown or JSON to stdout.
The Rust `StateStore::backup_to` API exports a validated database, available blobs, compact receipts, and a backup manifest.
The CLI does not expose that backup API as a command.

When changing model vendors, stop writers before copying the complete state and receipt directories.
Keep the database, blobs, JSON artifacts, and receipts together.
A new client must supply an adapter for these formats.
This repository provides no model-vendor adapter or hosted-model API integration.

## Limits

- The public core retrieves static HTTP content and parses local files.
- It does not render JavaScript pages or provide browser automation.
- Default network policy blocks private and loopback destinations outside explicit fixture tests.
- Project IDs isolate storage paths; callers still supply trusted identity and configuration.
- Downloaded content remains untrusted evidence.
- The workspace supplies no scheduler, daemon, outbound delivery service, or external-write consumer.
- The PDF dependency chain includes an unmaintained font parser with no patched version in its advisory.

See [dependency decisions and the saved security scan](DEPENDENCIES.md).

## Verify

```sh
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all
shellcheck examples/demo.sh
```

Install ShellCheck to lint the demo.

## Related repositories

- [owned-record](https://github.com/b2bvic/owned-record): Markdown context folders and routing configuration.
- [pretool-memory](https://github.com/b2bvic/pretool-memory): Recall owned records before selected tool calls.
- [cc-bridge](https://github.com/b2bvic/cc-bridge): Convert transcript exchanges to Markdown logs.
- [voice-calibration](https://github.com/b2bvic/voice-calibration): Recall writing samples for a target file genre.

## License

MIT. See [LICENSE](LICENSE).
