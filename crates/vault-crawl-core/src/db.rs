use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::hash::sha256_hex;

const MIGRATION_0001: &str = include_str!("../../../migrations/0001_phase0_contract.sql");
const MIGRATION_0002: &str = include_str!("../../../migrations/0002_phase1_runtime.sql");
const MIGRATION_0003: &str = include_str!("../../../migrations/0003_phase1_throttles.sql");
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
static TEMP_DATABASE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Migration {
    pub version: i64,
    pub name: &'static str,
    pub sql: &'static str,
    pub sha256: &'static str,
}

pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "phase0_contract",
        sql: MIGRATION_0001,
        sha256: "591ce67f186a7c091858a53f68101b5b314ce407f95e3ea950a69d90b0b2ccbe",
    },
    Migration {
        version: 2,
        name: "phase1_runtime",
        sql: MIGRATION_0002,
        sha256: "8cf634e1b163dcc4fb99062cde78548828f8f5d83b01cf62654d51ebc00eef62",
    },
    Migration {
        version: 3,
        name: "phase1_throttles",
        sql: MIGRATION_0003,
        sha256: "80f0c4653c05239cfdd121d81b7bc5a0a528e1758d5c8fb88384fee22c19d652",
    },
];

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MigrationStatus {
    pub latest_available: i64,
    pub latest_applied: i64,
    pub pending: usize,
    pub integrity: String,
    pub checksums_verified: usize,
}

/// Opens a lane-local `SQLite` database with the named Phase 0 operational
/// pragmas. Callers are responsible for selecting an already-authorized lane
/// root; this function never derives a root from untrusted input.
///
/// # Errors
///
/// Returns an error when the database cannot be opened or a required pragma
/// cannot be applied.
pub fn open(path: &Path) -> rusqlite::Result<Connection> {
    let connection = Connection::open(path)?;
    configure(&connection)?;
    Ok(connection)
}

/// Opens a transient database with the same operational pragmas as a lane
/// database.
///
/// # Errors
///
/// Returns an error when `SQLite` cannot create or configure the database.
pub fn open_in_memory() -> rusqlite::Result<Connection> {
    let connection = Connection::open_in_memory()?;
    configure(&connection)?;
    Ok(connection)
}

fn configure(connection: &Connection) -> rusqlite::Result<()> {
    connection.busy_timeout(BUSY_TIMEOUT)?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    Ok(())
}

/// Applies all known migrations transactionally. The migration record and its
/// schema changes commit together.
///
/// # Errors
///
/// Returns an error if a migration, record insertion, or integrity query fails.
pub fn migrate(connection: &mut Connection) -> rusqlite::Result<MigrationStatus> {
    verify_migration_definitions()?;
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (\
             version INTEGER PRIMARY KEY, \
             name TEXT NOT NULL UNIQUE, \
             checksum_sha256 TEXT NOT NULL, \
             applied_at_utc TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))\
         );",
    )?;
    verify_applied_migrations(connection)?;

    for migration in MIGRATIONS {
        let applied: Option<i64> = connection
            .query_row(
                "SELECT version FROM schema_migrations WHERE version = ?1",
                [migration.version],
                |row| row.get(0),
            )
            .optional()?;
        if applied.is_some() {
            continue;
        }

        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(migration.sql)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, name, checksum_sha256) VALUES (?1, ?2, ?3)",
            params![migration.version, migration.name, migration.sha256],
        )?;
        transaction.commit()?;
    }

    verify_applied_migrations(connection)?;

    status(connection)
}

/// Returns the latest applied migration and `SQLite` integrity result.
///
/// # Errors
///
/// Returns an error when the migration table or integrity pragma cannot be
/// queried.
pub fn status(connection: &Connection) -> rusqlite::Result<MigrationStatus> {
    let checksums_verified = verify_applied_migrations(connection)?;
    let latest_applied = connection
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0);
    let latest_available = MIGRATIONS.last().map_or(0, |migration| migration.version);
    let pending = MIGRATIONS
        .iter()
        .filter(|migration| migration.version > latest_applied)
        .count();
    let integrity = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;

    Ok(MigrationStatus {
        latest_available,
        latest_applied,
        pending,
        integrity,
        checksums_verified,
    })
}

fn verify_migration_definitions() -> rusqlite::Result<()> {
    for migration in MIGRATIONS {
        let actual = sha256_hex(migration.sql.as_bytes());
        if actual != migration.sha256 {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "migration {} SQL checksum drift: expected {}, got {actual}",
                migration.version, migration.sha256
            )));
        }
    }
    Ok(())
}

fn verify_applied_migrations(connection: &Connection) -> rusqlite::Result<usize> {
    let mut statement = connection
        .prepare("SELECT version, name, checksum_sha256 FROM schema_migrations ORDER BY version")?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    let mut verified = 0;
    for row in rows {
        let (version, name, checksum) = row?;
        let Some(expected) = MIGRATIONS
            .iter()
            .find(|migration| migration.version == version)
        else {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "unknown applied migration version {version}"
            )));
        };
        if name != expected.name || checksum != expected.sha256 {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "applied migration {version} metadata or checksum drift"
            )));
        }
        verified += 1;
    }
    Ok(verified)
}

/// Applies migrations twice to a new file-backed database, closes it, reopens
/// it, checks integrity, and removes the temporary database and sidecars.
///
/// # Errors
///
/// Returns an error when file creation, migration, idempotency, reopen,
/// integrity, or cleanup fails.
pub fn verify_temporary_migration() -> Result<MigrationStatus, String> {
    let sequence = TEMP_DATABASE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "vault-crawl-migration-{}-{sequence}.sqlite3",
        std::process::id()
    ));
    if path.exists() {
        return Err(format!(
            "temporary migration path already exists: {}",
            path.display()
        ));
    }

    let proof = (|| -> Result<MigrationStatus, String> {
        let mut connection = open(&path).map_err(|error| error.to_string())?;
        let first = migrate(&mut connection).map_err(|error| error.to_string())?;
        let second = migrate(&mut connection).map_err(|error| error.to_string())?;
        if first != second {
            return Err("second migration changed the applied state".to_owned());
        }
        drop(connection);

        let reopened = open(&path).map_err(|error| error.to_string())?;
        let reopened_status = status(&reopened).map_err(|error| error.to_string())?;
        if reopened_status != second {
            return Err("reopened migration state differs from committed state".to_owned());
        }
        drop(reopened);
        Ok(reopened_status)
    })();

    let cleanup = remove_database_files(&path);
    match (proof, cleanup) {
        (Ok(status), Ok(())) => Ok(status),
        (Err(error), _) | (Ok(_), Err(error)) => Err(error),
    }
}

fn remove_database_files(path: &Path) -> Result<(), String> {
    let mut candidates = vec![path.to_path_buf()];
    candidates.push(path.with_extension("sqlite3-wal"));
    candidates.push(path.with_extension("sqlite3-shm"));
    for candidate in candidates {
        match std::fs::remove_file(&candidate) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("remove {}: {error}", candidate.display())),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{MIGRATIONS, migrate, open_in_memory, verify_temporary_migration};

    #[test]
    fn fresh_database_migrates_forward_and_is_idempotent() {
        let mut connection = open_in_memory().expect("open in-memory database");
        let first = migrate(&mut connection).expect("first migration");
        assert_eq!(first.latest_applied, 3);
        assert_eq!(first.pending, 0);
        assert_eq!(first.integrity, "ok");
        assert_eq!(first.checksums_verified, 3);

        let second = migrate(&mut connection).expect("idempotent migration");
        assert_eq!(first, second);
    }

    #[test]
    fn canonical_tables_and_fts_index_exist() {
        let mut connection = open_in_memory().expect("open in-memory database");
        migrate(&mut connection).expect("migrate database");

        let required = [
            "crawl_jobs",
            "requests",
            "responses",
            "documents",
            "corpus_index",
            "links",
            "snapshots",
            "diffs",
            "adapter_runs",
            "source_registries",
            "provider_usage",
            "monitor_events",
            "receipts",
            "blob_objects",
            "http_cache",
            "robots_cache",
            "normalized_artifacts",
            "recovery_events",
            "request_throttles",
        ];

        for table in required {
            let count: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE name = ?1",
                    [table],
                    |row| row.get(0),
                )
                .expect("query sqlite schema");
            assert_eq!(count, 1, "missing table {table}");
        }
    }

    #[test]
    fn receipt_table_persists_canonical_envelope_and_operational_fields() {
        let mut connection = open_in_memory().expect("open in-memory database");
        migrate(&mut connection).expect("migrate database");
        let mut statement = connection
            .prepare("SELECT name FROM pragma_table_info('receipts')")
            .expect("prepare receipt column query");
        let columns = statement
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query receipt columns")
            .collect::<Result<BTreeSet<_>, _>>()
            .expect("collect receipt columns");
        for required in [
            "receipt_schema_version",
            "producer_version",
            "host_id",
            "source_hashes_json",
            "accepted_ids_json",
            "refused_ids_json",
            "counts_json",
            "budget_outcome",
            "software_version",
            "schema_versions_json",
            "adapter_version",
            "normalization_policy_version",
            "policy_hash",
            "configuration_hash",
            "seed_manifest_hash",
        ] {
            assert!(
                columns.contains(required),
                "missing receipt column {required}"
            );
        }
    }

    #[test]
    fn file_backed_temporary_database_is_idempotent_and_reopens() {
        let status = verify_temporary_migration().expect("verify temporary database migration");
        assert_eq!(status.latest_applied, 3);
        assert_eq!(status.pending, 0);
        assert_eq!(status.integrity, "ok");
        assert_eq!(status.checksums_verified, 3);
    }

    #[test]
    fn migration_checksum_is_persisted_and_drift_is_refused() {
        let mut connection = open_in_memory().expect("open in-memory database");
        migrate(&mut connection).expect("migrate database");
        let persisted: String = connection
            .query_row(
                "SELECT checksum_sha256 FROM schema_migrations WHERE version = 1",
                [],
                |row| row.get(0),
            )
            .expect("read persisted checksum");
        assert_eq!(persisted, MIGRATIONS[0].sha256);

        connection
            .execute(
                "UPDATE schema_migrations SET checksum_sha256 = 'drifted' WHERE version = 1",
                [],
            )
            .expect("inject migration drift");
        let error = migrate(&mut connection).expect_err("checksum drift must fail closed");
        assert!(error.to_string().contains("checksum drift"));
    }
}
