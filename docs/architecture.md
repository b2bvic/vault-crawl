# Public-core architecture

The workspace contains four crates:

- `vault-crawl-core` owns retrieval, extraction, persistence, schemas,
  migrations, project contracts, and threat decisions.
- `vault-crawl-adapters` represents inactive generic registry records and
  contains no source-specific API client.
- `vault-crawl-cli` exposes explicit foreground retrieval, parsing, search,
  status, doctor, and receipt commands.
- `vault-crawl-fixtures` serves locally authored deterministic files on a
  loopback address.

There is no daemon member, scheduler, service definition, browser process, or
external-write consumer in the public workspace.

## Project boundary

The caller selects a validated project ID. The core derives separate database,
blob, log, and receipt roots from that ID. No fixed project list or personal
filesystem layout is compiled into the application. The checked-in project
configuration is example-only.

## Trust boundary

Caller identity, source surface, project, capability ceiling, and output roots
are trusted configuration. Downloaded material cannot alter them. Requests may
narrow an authority ceiling but cannot expand it.

Static retrieval normalizes URLs, rejects ambient proxies, validates resolved
addresses, pins the selected address, checks the connected peer, and re-runs
policy across redirects. Downloaded material is stored as untrusted evidence
with hashes and provenance.

## Activation state

All commands are foreground operations. The fixture server is explicit,
loopback-only, and read-only. `doctor` checks repository contracts and
project-root isolation without network requests or external writes.
