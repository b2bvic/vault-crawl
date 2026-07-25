# ADR 0001: use rusqlite with bundled SQLite

Status: accepted for Phase 0

## Decision

Use `rusqlite` with the `bundled` feature. Keep migrations as ordered SQL files
applied inside `IMMEDIATE` transactions. Configure foreign keys, a five-second
busy timeout, and WAL mode at connection open.

## Reason

Phase 0 needs a small synchronous migration and diagnostic surface. A single
writer per lane is the planned runtime contract. `rusqlite` keeps the boundary
visible and avoids an async runtime before transport exists. Bundled SQLite
pins the engine used for FTS5 and reduces host ABI variance.

## Consequences

Linux releases must disclose SQLite linkage and pass the same fixture suite.
Phase 1 must add crash, lease, backup, corruption, and blob-reconciliation
proof before any runtime promotion. This ADR does not prove those behaviors.

