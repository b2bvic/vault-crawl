# ADR 0004: pinned x86_64 GNU/Linux release lane

Status: accepted for implementation before Linux release promotion

## Decision

Build the Linux release from the committed lockfile in a pinned Debian
Bookworm toolchain image using Rust 1.94.1 and target
`x86_64-unknown-linux-gnu`. Keep TLS in Rust when HTTP arrives and keep bundled
SQLite. Produce a binary checksum, Cargo lock hash, dependency inventory,
target triple, glibc baseline, build command, source commit, and rollback
artifact.

## Reason

Target hosts do not require a Rust toolchain. Runtime environments should
receive a reproducible artifact, not an ad hoc on-host compile. The baseline
must be compatible with the oldest supported target host.

## Consequences

Phase 0 is verified on the development host only. AC-002 remains unclaimed
until the exact Linux artifact passes the complete fixture suite on its target
host. No deployment or toolchain installation is part of Phase 0.
