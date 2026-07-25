#![allow(clippy::missing_errors_doc, clippy::too_many_lines)]

use std::fs::{self, File, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::{Connection, MAIN_DB, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::PRODUCER_VERSION;
use crate::contract::{Lane, SourceSurface};
use crate::db;
use crate::error::{CrawlError, Result};
use crate::extract::ExtractedDocument;
use crate::hash::sha256_hex;
use crate::policy::{ApprovedDestination, NormalizedUrl};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobRecord {
    pub sha256: String,
    pub relative_path: String,
    pub byte_count: usize,
    pub availability_state: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Receipt {
    pub receipt_schema_version: String,
    pub producer_version: String,
    pub run_id: String,
    pub parent_run_id: Option<String>,
    pub host_id: String,
    pub caller: String,
    pub source_surface: String,
    pub lane: String,
    pub command: String,
    pub inspected_scope: Value,
    pub terminal_outcome: String,
    pub counts: Value,
    pub budget_outcome: String,
    pub monotonic_duration_ms: u64,
    pub artifact_paths: Vec<String>,
    pub source_hashes: Vec<String>,
    pub error_summary: Option<String>,
    pub software_version: String,
    pub normalization_policy_version: String,
    pub policy_hash: String,
    pub configuration_hash: String,
    pub seed_manifest_hash: String,
    pub created_at_utc: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryHit {
    pub document_id: String,
    pub caller: String,
    pub lane: String,
    pub adapter: String,
    pub host_id: String,
    pub title: String,
    pub normalized_url: String,
    pub content_hash: String,
    pub captured_at_utc: String,
    pub snippet: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryFilter {
    pub caller: Option<String>,
    pub lane: Option<String>,
    pub adapter: Option<String>,
    pub host_id: Option<String>,
}

#[derive(Debug)]
struct RebuildArtifact {
    document_id: String,
    title: String,
    text_hash: String,
    host_id: String,
    captured_at_utc: String,
    caller: String,
    lane: String,
    adapter: String,
}

#[derive(Debug)]
pub struct StateStore {
    root: PathBuf,
    database: PathBuf,
    blobs: PathBuf,
    artifacts: PathBuf,
    receipt_root: PathBuf,
    connection: Connection,
}

#[derive(Debug)]
pub struct PersistInput<'a> {
    pub run_id: &'a str,
    pub idempotency_key: &'a str,
    pub caller: &'a str,
    pub lane: Lane,
    pub source_surface: SourceSurface,
    pub host_id: &'a str,
    pub command: &'a str,
    pub normalized: &'a NormalizedUrl,
    pub destination: &'a ApprovedDestination,
    pub status: u16,
    pub final_url: &'a str,
    pub selected_headers: &'a Value,
    pub content_type: &'a str,
    pub etag: Option<&'a str>,
    pub last_modified: Option<&'a str>,
    pub entity: &'a BlobRecord,
    pub document: Option<&'a ExtractedDocument>,
    pub markdown_blob: Option<&'a BlobRecord>,
    pub text_blob: Option<&'a BlobRecord>,
    pub elapsed_ms: u64,
    pub cache_outcome: &'a str,
    pub robots_decision: &'a str,
    pub robots_reason: &'a str,
    pub redirects: &'a [RedirectRecord],
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RedirectRecord {
    pub from_url: String,
    pub to_url: String,
    pub status: u16,
    pub selected_headers: Value,
    pub destination: ApprovedDestination,
    pub robots_decision: String,
    pub robots_reason: String,
}

impl StateStore {
    pub fn open(root: &Path, receipt_root: &Path) -> Result<Self> {
        create_private_directory(root)?;
        let blobs = root.join("blobs");
        let artifacts = root.join("artifacts");
        create_private_directory(&blobs)?;
        create_private_directory(&blobs.join(".tmp"))?;
        create_private_directory(&artifacts)?;
        create_private_directory(receipt_root)?;
        let database = root.join("state.sqlite3");
        let mut connection = db::open(&database)?;
        db::migrate(&mut connection)?;
        Ok(Self {
            root: root.to_path_buf(),
            database,
            blobs,
            artifacts,
            receipt_root: receipt_root.to_path_buf(),
            connection,
        })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn store_blob(
        &mut self,
        bytes: &[u8],
        media_class: &str,
        retention_class: &str,
        strong_pin: bool,
    ) -> Result<BlobRecord> {
        self.store_blob_reader(
            Cursor::new(bytes),
            bytes.len(),
            media_class,
            retention_class,
            strong_pin,
        )
        .map(|(record, _)| record)
    }

    pub fn store_blob_reader<R: Read>(
        &mut self,
        mut reader: R,
        max_bytes: usize,
        media_class: &str,
        retention_class: &str,
        strong_pin: bool,
    ) -> Result<(BlobRecord, Vec<u8>)> {
        let temporary =
            self.blobs
                .join(".tmp")
                .join(format!("{}.{}.tmp", std::process::id(), Uuid::new_v4()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        let mut hasher = Sha256::new();
        let mut bytes = Vec::with_capacity(max_bytes.min(64 * 1024));
        let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
        let streamed = (|| -> Result<()> {
            loop {
                let count = reader.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                if bytes.len().saturating_add(count) > max_bytes {
                    return Err(CrawlError::Refused(format!(
                        "response body exceeds byte budget {max_bytes}"
                    )));
                }
                file.write_all(&buffer[..count])?;
                hasher.update(&buffer[..count]);
                bytes.extend_from_slice(&buffer[..count]);
            }
            file.sync_all()?;
            Ok(())
        })();
        if let Err(error) = streamed {
            drop(file);
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        drop(file);
        let sha256 = format!("{:x}", hasher.finalize());
        let relative_path = format!("{}/{}", &sha256[..2], &sha256[2..]);
        let destination = self.blobs.join(&relative_path);
        if destination.exists() {
            let existing = fs::read(&destination)?;
            if existing.len() != bytes.len() || sha256_hex(&existing) != sha256 {
                fs::remove_file(&temporary)?;
                return Err(CrawlError::Storage(
                    "content-addressed blob collision or corruption".to_owned(),
                ));
            }
            fs::remove_file(&temporary)?;
        } else {
            let parent = destination
                .parent()
                .ok_or_else(|| CrawlError::Storage("blob has no parent directory".to_owned()))?;
            create_private_directory(parent)?;
            match fs::rename(&temporary, &destination) {
                Ok(()) => {}
                Err(error) if destination.exists() => {
                    fs::remove_file(&temporary)?;
                    let existing = fs::read(&destination)?;
                    if sha256_hex(&existing) != sha256 {
                        return Err(CrawlError::Storage(format!(
                            "existing blob hash mismatch after rename race: {error}"
                        )));
                    }
                }
                Err(error) => return Err(CrawlError::Io(error)),
            }
            File::open(parent)?.sync_all()?;
        }
        let now = now_utc();
        self.connection.execute(
            "INSERT INTO blob_objects(sha256, relative_path, byte_count, media_class, retention_class, strong_pins, availability_state, created_at_utc, verified_at_utc) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'available-local', ?7, ?7)\
             ON CONFLICT(sha256) DO UPDATE SET verified_at_utc=excluded.verified_at_utc, availability_state='available-local', strong_pins=MAX(blob_objects.strong_pins, excluded.strong_pins)",
            params![
                sha256,
                relative_path,
                i64::try_from(bytes.len()).map_err(|_| CrawlError::Storage("blob too large".to_owned()))?,
                media_class,
                retention_class,
                i64::from(strong_pin),
                now,
            ],
        )?;
        Ok((
            BlobRecord {
                sha256,
                relative_path,
                byte_count: bytes.len(),
                availability_state: "available-local".to_owned(),
            },
            bytes,
        ))
    }

    pub fn cache_entry(&self, normalized_url: &str) -> Result<Option<CachedResponse>> {
        self.connection
            .query_row(
                "SELECT final_url, status, selected_headers_json, content_type, etag, last_modified, entity_body_sha256, captured_at_utc \
                 FROM http_cache WHERE normalized_url=?1",
                [normalized_url],
                |row| {
                    Ok(CachedResponse {
                        final_url: row.get(0)?,
                        status: row.get::<_, u16>(1)?,
                        selected_headers: serde_json::from_str(&row.get::<_, String>(2)?)
                            .unwrap_or_else(|_| json!({})),
                        content_type: row.get(3)?,
                        etag: row.get(4)?,
                        last_modified: row.get(5)?,
                        entity_body_sha256: row.get(6)?,
                        captured_at_utc: row.get(7)?,
                    })
                },
            )
            .optional()
            .map_err(CrawlError::from)
    }

    pub fn robots_entry(&self, origin: &str) -> Result<Option<CachedRobots>> {
        Ok(self
            .robots_entry_with_freshness(origin)?
            .and_then(|(entry, fresh)| fresh.then_some(entry)))
    }

    pub fn robots_entry_with_freshness(
        &self,
        origin: &str,
    ) -> Result<Option<(CachedRobots, bool)>> {
        let entry = self
            .connection
            .query_row(
                "SELECT robots_url,status,body_sha256,fetched_at_utc,expires_at_utc,decision_class,redacted_reason FROM robots_cache WHERE origin=?1",
                [origin],
                |row| {
                    Ok(CachedRobots {
                        robots_url: row.get(0)?,
                        status: row.get(1)?,
                        body_sha256: row.get(2)?,
                        fetched_at_utc: row.get(3)?,
                        expires_at_utc: row.get(4)?,
                        decision_class: row.get(5)?,
                        redacted_reason: row.get(6)?,
                    })
                },
            )
            .optional()?;
        let Some(entry) = entry else {
            return Ok(None);
        };
        let expires = DateTime::parse_from_rfc3339(&entry.expires_at_utc)
            .map_err(|error| CrawlError::Storage(format!("invalid robots cache expiry: {error}")))?
            .with_timezone(&Utc);
        Ok(Some((entry, expires > Utc::now())))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn cache_robots(
        &self,
        origin: &str,
        robots_url: &str,
        status: Option<u16>,
        body_sha256: Option<&str>,
        ttl_seconds: u64,
        decision_class: &str,
        reason: &str,
    ) -> Result<()> {
        let now = Utc::now();
        let ttl = i64::try_from(ttl_seconds).unwrap_or(i64::MAX);
        let expires = now
            .checked_add_signed(chrono::Duration::seconds(ttl))
            .ok_or_else(|| CrawlError::InvalidInput("robots cache TTL overflow".to_owned()))?;
        self.connection.execute(
            "INSERT INTO robots_cache(origin,robots_url,status,body_sha256,fetched_at_utc,expires_at_utc,decision_class,redacted_reason) VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(origin) DO UPDATE SET robots_url=excluded.robots_url,status=excluded.status,body_sha256=excluded.body_sha256,fetched_at_utc=excluded.fetched_at_utc,expires_at_utc=excluded.expires_at_utc,decision_class=excluded.decision_class,redacted_reason=excluded.redacted_reason",
            params![
                origin,
                robots_url,
                status,
                body_sha256,
                now.to_rfc3339_opts(SecondsFormat::Millis, true),
                expires.to_rfc3339_opts(SecondsFormat::Millis, true),
                decision_class,
                reason,
            ],
        )?;
        Ok(())
    }

    pub fn reserve_request(
        &mut self,
        origin: &str,
        destination_ip: &str,
        minimum_delay_ms: u64,
        max_origin_requests_per_day: u64,
        max_ip_requests_per_day: u64,
    ) -> Result<ThrottleReservation> {
        let now = Utc::now();
        let usage_date = now.date_naive().format("%Y.%m.%d").to_string();
        let now_text = now.to_rfc3339_opts(SecondsFormat::Millis, true);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let origin_wait = reserve_throttle_scope(
            &transaction,
            "origin",
            origin,
            &usage_date,
            &now_text,
            now,
            minimum_delay_ms,
            max_origin_requests_per_day,
        )?;
        let ip_wait = reserve_throttle_scope(
            &transaction,
            "destination-ip",
            destination_ip,
            &usage_date,
            &now_text,
            now,
            minimum_delay_ms,
            max_ip_requests_per_day,
        )?;
        transaction.commit()?;
        Ok(ThrottleReservation {
            wait_ms: origin_wait.max(ip_wait),
            origin: origin.to_owned(),
            destination_ip: destination_ip.to_owned(),
            usage_date_utc: usage_date,
        })
    }

    pub fn record_response_bytes(
        &self,
        reservation: &ThrottleReservation,
        bytes: usize,
    ) -> Result<()> {
        let bytes = i64::try_from(bytes)
            .map_err(|_| CrawlError::Storage("response byte count overflow".to_owned()))?;
        for (scope_type, scope_value) in [
            ("origin", reservation.origin.as_str()),
            ("destination-ip", reservation.destination_ip.as_str()),
        ] {
            self.connection.execute(
                "UPDATE request_throttles SET byte_count=byte_count+?1 WHERE scope_type=?2 AND scope_value=?3 AND usage_date_utc=?4",
                params![bytes, scope_type, scope_value, reservation.usage_date_utc],
            )?;
        }
        Ok(())
    }

    pub fn enforce_storage_quota(
        &mut self,
        max_bytes: u64,
        reservation_bytes: u64,
    ) -> Result<QuotaReport> {
        if reservation_bytes > max_bytes {
            return Err(CrawlError::Refused(format!(
                "requested storage reservation {reservation_bytes} exceeds quota {max_bytes}"
            )));
        }
        let mut used = self.available_blob_bytes()?;
        let before = used;
        let mut evicted_blobs = 0_usize;
        let candidates: Vec<(String, String, i64)> = {
            let mut statement = self.connection.prepare(
                "SELECT b.sha256,b.relative_path,b.byte_count FROM blob_objects b WHERE b.availability_state='available-local' AND b.strong_pins=0 AND NOT EXISTS(SELECT 1 FROM responses r WHERE r.entity_body_sha256=b.sha256) AND NOT EXISTS(SELECT 1 FROM documents d WHERE d.primary_markdown_sha256=b.sha256 OR d.primary_text_sha256=b.sha256) AND NOT EXISTS(SELECT 1 FROM robots_cache rc WHERE rc.body_sha256=b.sha256) AND NOT EXISTS(SELECT 1 FROM normalized_artifacts a WHERE a.markdown_sha256=b.sha256 OR a.text_sha256=b.sha256) ORDER BY b.created_at_utc,b.sha256",
            )?;
            statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        for (sha256, relative_path, byte_count) in candidates {
            if used.saturating_add(reservation_bytes) <= max_bytes {
                break;
            }
            let path = self.blobs.join(relative_path);
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(CrawlError::Io(error)),
            }
            self.connection.execute(
                "UPDATE blob_objects SET availability_state='evicted-under-policy' WHERE sha256=?1 AND strong_pins=0",
                [&sha256],
            )?;
            used = used.saturating_sub(u64::try_from(byte_count).unwrap_or(0));
            evicted_blobs += 1;
        }
        if used.saturating_add(reservation_bytes) > max_bytes {
            return Err(CrawlError::Refused(format!(
                "storage quota {max_bytes} cannot reserve {reservation_bytes}; {used} bytes are retained or pinned"
            )));
        }
        Ok(QuotaReport {
            used_before_bytes: before,
            used_after_bytes: used,
            reserved_bytes: reservation_bytes,
            evicted_blobs,
        })
    }

    fn available_blob_bytes(&self) -> Result<u64> {
        let count: i64 = self.connection.query_row(
            "SELECT COALESCE(SUM(byte_count),0) FROM blob_objects WHERE availability_state='available-local'",
            [],
            |row| row.get(0),
        )?;
        u64::try_from(count).map_err(|_| CrawlError::Storage("negative blob usage".to_owned()))
    }

    pub fn read_blob(&self, sha256: &str) -> Result<Vec<u8>> {
        if sha256.len() != 64 {
            return Err(CrawlError::InvalidInput("invalid blob hash".to_owned()));
        }
        let relative: Option<String> = self
            .connection
            .query_row(
                "SELECT relative_path FROM blob_objects WHERE sha256=?1 AND availability_state='available-local'",
                [sha256],
                |row| row.get(0),
            )
            .optional()?;
        let relative = relative.ok_or_else(|| {
            CrawlError::Storage(format!("blob {sha256} is not available locally"))
        })?;
        let path = self.blobs.join(relative);
        let bytes = fs::read(path)?;
        if sha256_hex(&bytes) != sha256 {
            return Err(CrawlError::Storage(format!(
                "blob {sha256} failed verification"
            )));
        }
        Ok(bytes)
    }

    pub fn persist_fetch(&mut self, input: &PersistInput<'_>) -> Result<PersistedFetch> {
        let job_id = sha256_hex(format!("crawl-job:v1:{}", input.idempotency_key).as_bytes());
        let request_id = Uuid::new_v4().to_string();
        let response_id = Uuid::new_v4().to_string();
        let document_id = input.document.map(|_| {
            sha256_hex(
                format!(
                    "document:v1:{}:static-http:{}",
                    lane_name(&input.lane),
                    input.normalized.normalized
                )
                .as_bytes(),
            )
        });
        let now = now_utc();
        let selected_address = input.destination.selected.to_string();
        let resolved_addresses = serde_json::to_string(&input.destination.addresses)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO crawl_jobs(job_id,idempotency_key,caller,source_surface,lane,execution_host,purpose,priority,policy_profile,seed_set_json,adapter,created_at_utc,started_at_utc,completed_at_utc,page_budget,byte_budget,time_budget_ms,depth_budget,origin_budget,state,attempt_count,policy_hash,configuration_hash,seed_manifest_hash,normalization_policy_version,software_hash) \
             VALUES(?1,?2,?3,?4,?5,?6,?7,0,'automatic-public',?8,'static-http',?9,?9,?9,1,?10,30000,0,1,'success',1,?11,?11,?11,?12,?11) \
             ON CONFLICT(idempotency_key) DO UPDATE SET started_at_utc=excluded.started_at_utc,completed_at_utc=excluded.completed_at_utc,state='success',attempt_count=crawl_jobs.attempt_count+1",
            params![
                job_id,
                input.idempotency_key,
                input.caller,
                surface_name(input.source_surface),
                lane_name(&input.lane),
                input.host_id,
                input.command,
                serde_json::to_string(&[input.normalized.normalized.as_str()])?,
                now,
                i64::try_from(input.entity.byte_count).unwrap_or(i64::MAX),
                sha256_hex(b"phase1-default"),
                input.normalized.normalization_policy_version,
            ],
        )?;
        let attempt: i64 = transaction.query_row(
            "SELECT attempt_count FROM crawl_jobs WHERE idempotency_key=?1",
            [input.idempotency_key],
            |row| row.get(0),
        )?;
        let mut redirect_parent_request_id: Option<String> = None;
        for redirect in input.redirects {
            let redirect_request_id = Uuid::new_v4().to_string();
            let redirect_response_id = Uuid::new_v4().to_string();
            transaction.execute(
                "INSERT INTO requests(request_id,job_id,original_url,normalized_url,method,request_headers_allowlist_json,attempt,normalized_host,resolved_addresses_json,selected_pinned_address,connected_peer_address,port,redirect_parent_request_id,robots_decision,robots_reason,state,scheduled_at_utc,started_at_utc,finished_at_utc,monotonic_duration_ms,retry_eligible,terminal_reason) VALUES(?1,?2,?3,?3,'GET','[]',?4,?5,?6,?7,?7,?8,?9,?10,?11,'completed',?12,?12,?12,0,0,?13)",
                params![
                    redirect_request_id,
                    job_id,
                    redirect.from_url,
                    attempt,
                    redirect.destination.host,
                    serde_json::to_string(&redirect.destination.addresses)?,
                    redirect.destination.selected.to_string(),
                    redirect.destination.port,
                    redirect_parent_request_id,
                    redirect.robots_decision,
                    redirect.robots_reason,
                    now,
                    format!("redirect {} to {}", redirect.status, redirect.to_url),
                ],
            )?;
            transaction.execute(
                "INSERT INTO responses(response_id,request_id,final_url,status,selected_headers_json,byte_count,elapsed_ms,cache_outcome,render_state,host_id,retention_class,reference_count,hold_state,availability_state) VALUES(?1,?2,?3,?4,?5,0,0,'redirect','not-needed',?6,'transient',0,'none','hash-known')",
                params![
                    redirect_response_id,
                    redirect_request_id,
                    redirect.to_url,
                    redirect.status,
                    redirect.selected_headers.to_string(),
                    input.host_id,
                ],
            )?;
            redirect_parent_request_id = Some(redirect_request_id);
        }
        transaction.execute(
            "INSERT INTO requests(request_id,job_id,original_url,normalized_url,method,request_headers_allowlist_json,attempt,normalized_host,resolved_addresses_json,selected_pinned_address,connected_peer_address,port,redirect_parent_request_id,robots_decision,robots_reason,state,scheduled_at_utc,started_at_utc,finished_at_utc,monotonic_duration_ms,retry_eligible) \
             VALUES(?1,?2,?3,?4,'GET','[]',?5,?6,?7,?8,?8,?9,?10,?11,?12,'completed',?13,?13,?13,?14,0)",
            params![
                request_id,
                job_id,
                input.normalized.original,
                input.normalized.normalized.as_str(),
                attempt,
                input.destination.host,
                resolved_addresses,
                selected_address,
                input.destination.port,
                redirect_parent_request_id,
                input.robots_decision,
                input.robots_reason,
                now,
                i64::try_from(input.elapsed_ms).unwrap_or(i64::MAX),
            ],
        )?;
        let parsed_hash = input
            .document
            .map(|document| document.parsed_sha256.as_str());
        let parser = input.document.map(|document| document.parser.as_str());
        let parser_version = input
            .document
            .map(|document| document.parser_version.as_str());
        let render_state = if input.document.is_some_and(|document| document.needs_render) {
            "needs-render"
        } else {
            "not-needed"
        };
        transaction.execute(
            "INSERT INTO responses(response_id,request_id,final_url,status,selected_headers_json,content_type,byte_count,elapsed_ms,entity_body_sha256,parsed_body_sha256,etag,last_modified,cache_outcome,parser,parser_version,render_state,host_id,store_id,retention_class,reference_count,hold_state,availability_state) \
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?9,'standard',1,'none','available-local')",
            params![
                response_id,
                request_id,
                input.final_url,
                input.status,
                input.selected_headers.to_string(),
                input.content_type,
                i64::try_from(input.entity.byte_count).unwrap_or(i64::MAX),
                i64::try_from(input.elapsed_ms).unwrap_or(i64::MAX),
                input.entity.sha256,
                parsed_hash,
                input.etag,
                input.last_modified,
                input.cache_outcome,
                parser,
                parser_version,
                render_state,
                input.host_id,
            ],
        )?;
        if let (Some(document), Some(document_id), Some(markdown), Some(text)) = (
            input.document,
            document_id.as_deref(),
            input.markdown_blob,
            input.text_blob,
        ) {
            let raw_pointer = json!({"host_id":input.host_id,"store_id":input.entity.sha256,"availability":"available-local"});
            let artifact_pointer = json!({"markdown_sha256":markdown.sha256,"text_sha256":text.sha256,"availability":"available-local"});
            let mut identity_history = transaction
                .query_row(
                    "SELECT identity_history_json FROM documents WHERE document_id=?1",
                    [document_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .and_then(|value| serde_json::from_str::<Vec<Value>>(&value).ok())
                .unwrap_or_default();
            identity_history.push(json!({
                "response_id":response_id,
                "observed_canonical_url":document.canonical_url,
                "captured_at_utc":now,
            }));
            transaction.execute(
                "INSERT INTO documents(document_id,response_id,normalized_url_identity,observed_canonical_url,title,description,author,primary_markdown_sha256,primary_text_sha256,language,word_count,headings_json,metadata_json,open_graph_json,json_ld_json,schema_types_json,raw_evidence_pointer_json,normalized_artifact_pointer_json,identity_history_json) \
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19) \
                 ON CONFLICT(document_id) DO UPDATE SET response_id=excluded.response_id,observed_canonical_url=excluded.observed_canonical_url,title=excluded.title,description=excluded.description,author=excluded.author,primary_markdown_sha256=excluded.primary_markdown_sha256,primary_text_sha256=excluded.primary_text_sha256,language=excluded.language,word_count=excluded.word_count,headings_json=excluded.headings_json,metadata_json=excluded.metadata_json,open_graph_json=excluded.open_graph_json,json_ld_json=excluded.json_ld_json,schema_types_json=excluded.schema_types_json,raw_evidence_pointer_json=excluded.raw_evidence_pointer_json,normalized_artifact_pointer_json=excluded.normalized_artifact_pointer_json,identity_history_json=excluded.identity_history_json",
                params![
                    document_id,
                    response_id,
                    input.normalized.normalized.as_str(),
                    document.canonical_url,
                    document.title,
                    document.description,
                    document.author,
                    markdown.sha256,
                    text.sha256,
                    document.language,
                    i64::try_from(document.word_count).unwrap_or(i64::MAX),
                    serde_json::to_string(&document.headings)?,
                    serde_json::to_string(&document.metadata)?,
                    serde_json::to_string(&document.open_graph)?,
                    serde_json::to_string(&document.json_ld)?,
                    serde_json::to_string(&document.schema_types)?,
                    raw_pointer.to_string(),
                    artifact_pointer.to_string(),
                    serde_json::to_string(&identity_history)?,
                ],
            )?;
            transaction.execute(
                "DELETE FROM links WHERE source_document_id=?1",
                [document_id],
            )?;
            for link in &document.links {
                transaction.execute(
                    "INSERT INTO links(link_id,source_document_id,raw_target,resolved_target,normalized_target,relation,anchor_text,location,nofollow,classification) VALUES(?1,?2,?3,?4,?4,?5,?6,'document',?7,?8)",
                    params![
                        Uuid::new_v4().to_string(),
                        document_id,
                        link.raw_target,
                        link.resolved_target,
                        link.relation,
                        link.anchor_text,
                        i64::from(link.nofollow),
                        link.classification,
                    ],
                )?;
            }
            transaction.execute(
                "INSERT INTO normalized_artifacts(document_id,markdown_sha256,text_sha256,manifest_json,created_at_utc) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(document_id) DO UPDATE SET markdown_sha256=excluded.markdown_sha256,text_sha256=excluded.text_sha256,manifest_json=excluded.manifest_json,created_at_utc=excluded.created_at_utc",
                params![document_id, markdown.sha256, text.sha256, serde_json::to_string(document)?, now],
            )?;
            transaction.execute(
                "DELETE FROM corpus_index WHERE document_id=?1",
                [document_id],
            )?;
            transaction.execute(
                "INSERT INTO corpus_index(document_id,caller,lane,adapter,host_id,captured_at_utc,content_hash,index_schema_version,title,body) VALUES(?1,?2,?3,'static-http',?4,?5,?6,'1.0.0',?7,?8)",
                params![
                    document_id,
                    input.caller,
                    lane_name(&input.lane),
                    input.host_id,
                    now,
                    document.parsed_sha256,
                    document.title.as_deref().unwrap_or_default(),
                    document.primary_text,
                ],
            )?;
        }
        transaction.execute(
            "INSERT INTO http_cache(normalized_url,response_id,final_url,status,selected_headers_json,content_type,etag,last_modified,entity_body_sha256,captured_at_utc) \
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) \
             ON CONFLICT(normalized_url) DO UPDATE SET response_id=excluded.response_id,final_url=excluded.final_url,status=excluded.status,selected_headers_json=excluded.selected_headers_json,content_type=excluded.content_type,etag=excluded.etag,last_modified=excluded.last_modified,entity_body_sha256=excluded.entity_body_sha256,captured_at_utc=excluded.captured_at_utc",
            params![
                input.normalized.normalized.as_str(),
                response_id,
                input.final_url,
                input.status,
                input.selected_headers.to_string(),
                input.content_type,
                input.etag,
                input.last_modified,
                input.entity.sha256,
                now,
            ],
        )?;
        transaction.commit()?;

        let manifest_path = document_id
            .as_ref()
            .map(|document_id| self.artifacts.join(format!("{document_id}.manifest.json")));
        if let (Some(path), Some(document)) = (&manifest_path, input.document) {
            atomic_private_write(path, serde_json::to_vec_pretty(document)?.as_slice())?;
        }
        Ok(PersistedFetch {
            job_id,
            request_id,
            response_id,
            document_id,
            manifest_path,
        })
    }

    pub fn write_receipt(&mut self, receipt: &Receipt) -> Result<PathBuf> {
        let date = receipt
            .created_at_utc
            .get(..10)
            .unwrap_or("unknown")
            .replace('-', ".");
        let encoded = serde_json::to_vec_pretty(receipt)?;
        let primary_directory = self.receipt_root.join(&date);
        let primary_path =
            primary_directory.join(format!("{}-{}.json", receipt.host_id, receipt.run_id));
        let primary_write = create_private_directory(&primary_directory)
            .and_then(|()| atomic_private_write(&primary_path, &encoded));
        let (path, delivery_state) = if primary_write.is_ok() {
            (primary_path, "not-required")
        } else {
            let emergency_directory = self.root.join("emergency-receipts").join(date);
            create_private_directory(&emergency_directory)?;
            let emergency_path = emergency_directory.join(format!(
                "{}-{}-compact-fallback.json",
                receipt.host_id, receipt.run_id
            ));
            atomic_private_write(&emergency_path, &encoded)?;
            (emergency_path, "compact-fallback")
        };
        self.connection.execute(
            "INSERT INTO receipts(run_id,parent_run_id,receipt_schema_version,producer_version,host_id,source_hashes_json,caller,source_surface,lane,command,execution_host,inspected_scope_json,accepted_ids_json,refused_ids_json,terminal_outcome,counts_json,budget_outcome,monotonic_duration_ms,artifact_paths_json,delivery_state,error_summary,software_commit,software_version,schema_versions_json,adapter_version,normalization_policy_version,policy_hash,configuration_hash,seed_manifest_hash,evidence_availability_state,compact_receipt_path,created_at_utc) \
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?5,?11,'[]','[]',?12,?13,?14,?15,?16,?17,?18,'working-tree',?19,'{\"database\":3,\"artifact\":1}',NULL,?20,?21,?22,?23,'available-local',?24,?25)",
            params![
                receipt.run_id,
                receipt.parent_run_id,
                receipt.receipt_schema_version,
                receipt.producer_version,
                receipt.host_id,
                serde_json::to_string(&receipt.source_hashes)?,
                receipt.caller,
                receipt.source_surface,
                receipt.lane,
                receipt.command,
                receipt.inspected_scope.to_string(),
                receipt.terminal_outcome,
                receipt.counts.to_string(),
                receipt.budget_outcome,
                i64::try_from(receipt.monotonic_duration_ms).unwrap_or(i64::MAX),
                serde_json::to_string(&receipt.artifact_paths)?,
                delivery_state,
                receipt.error_summary,
                receipt.software_version,
                receipt.normalization_policy_version,
                receipt.policy_hash,
                receipt.configuration_hash,
                receipt.seed_manifest_hash,
                path.to_string_lossy(),
                receipt.created_at_utc,
            ],
        )?;
        Ok(path)
    }

    pub fn write_artifact(&self, artifact_id: &str, value: &Value) -> Result<PathBuf> {
        if artifact_id.is_empty()
            || !artifact_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(CrawlError::InvalidInput(
                "artifact ID contains unsafe characters".to_owned(),
            ));
        }
        let path = self.artifacts.join(format!("{artifact_id}.json"));
        atomic_private_write(&path, serde_json::to_vec_pretty(value)?.as_slice())?;
        Ok(path)
    }

    pub fn query(&self, query: &str, limit: usize) -> Result<Vec<QueryHit>> {
        self.query_filtered(query, limit, &QueryFilter::default())
    }

    pub fn query_filtered(
        &self,
        query: &str,
        limit: usize,
        filter: &QueryFilter,
    ) -> Result<Vec<QueryHit>> {
        if query.trim().is_empty() || limit == 0 || limit > 100 {
            return Err(CrawlError::InvalidInput(
                "query must be non-empty and limit must be 1..=100".to_owned(),
            ));
        }
        let mut statement = self.connection.prepare(
            "SELECT c.document_id, c.caller, c.lane, c.adapter, c.host_id, COALESCE(d.title,''), d.normalized_url_identity, c.content_hash, c.captured_at_utc, snippet(corpus_index, 10, '[', ']', ' … ', 24) \
             FROM corpus_index c JOIN documents d ON d.document_id=c.document_id \
             WHERE corpus_index MATCH ?1 \
               AND (?2 IS NULL OR c.caller=?2) \
               AND (?3 IS NULL OR c.lane=?3) \
               AND (?4 IS NULL OR c.adapter=?4) \
               AND (?5 IS NULL OR c.host_id=?5) \
             ORDER BY rank LIMIT ?6",
        )?;
        let rows = statement.query_map(
            params![
                query,
                filter.caller,
                filter.lane,
                filter.adapter,
                filter.host_id,
                i64::try_from(limit).unwrap_or(100)
            ],
            |row| {
                Ok(QueryHit {
                    document_id: row.get(0)?,
                    caller: row.get(1)?,
                    lane: row.get(2)?,
                    adapter: row.get(3)?,
                    host_id: row.get(4)?,
                    title: row.get(5)?,
                    normalized_url: row.get(6)?,
                    content_hash: row.get(7)?,
                    captured_at_utc: row.get(8)?,
                    snippet: row.get(9)?,
                })
            },
        )?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(CrawlError::from)
    }

    pub fn receipt_value(&self, run_id: &str) -> Result<Value> {
        self.connection
            .query_row(
                "SELECT receipt_schema_version,producer_version,host_id,source_hashes_json,caller,source_surface,lane,command,inspected_scope_json,terminal_outcome,counts_json,budget_outcome,monotonic_duration_ms,artifact_paths_json,delivery_state,error_summary,software_commit,software_version,schema_versions_json,normalization_policy_version,policy_hash,configuration_hash,seed_manifest_hash FROM receipts WHERE run_id=?1",
                [run_id],
                |row| {
                    Ok(json!({
                        "run_id":run_id,
                        "receipt_schema_version":row.get::<_,String>(0)?,
                        "producer_version":row.get::<_,String>(1)?,
                        "host_id":row.get::<_,String>(2)?,
                        "source_hashes":serde_json::from_str::<Value>(&row.get::<_,String>(3)?).unwrap_or_else(|_| json!([])),
                        "caller":row.get::<_,String>(4)?,
                        "source_surface":row.get::<_,String>(5)?,
                        "lane":row.get::<_,String>(6)?,
                        "command":row.get::<_,String>(7)?,
                        "inspected_scope":serde_json::from_str::<Value>(&row.get::<_,String>(8)?).unwrap_or_else(|_| json!({})),
                        "terminal_outcome":row.get::<_,String>(9)?,
                        "counts":serde_json::from_str::<Value>(&row.get::<_,String>(10)?).unwrap_or_else(|_| json!({})),
                        "budget_outcome":row.get::<_,String>(11)?,
                        "monotonic_duration_ms":row.get::<_,i64>(12)?,
                        "artifact_paths":serde_json::from_str::<Value>(&row.get::<_,String>(13)?).unwrap_or_else(|_| json!([])),
                        "delivery_state":row.get::<_,String>(14)?,
                        "error_summary":row.get::<_,Option<String>>(15)?,
                        "software_commit":row.get::<_,String>(16)?,
                        "software_version":row.get::<_,String>(17)?,
                        "schema_versions":serde_json::from_str::<Value>(&row.get::<_,String>(18)?).unwrap_or_else(|_| json!({})),
                        "normalization_policy_version":row.get::<_,String>(19)?,
                        "policy_hash":row.get::<_,String>(20)?,
                        "configuration_hash":row.get::<_,String>(21)?,
                        "seed_manifest_hash":row.get::<_,String>(22)?,
                    }))
                },
            )
            .optional()?
            .ok_or_else(|| CrawlError::InvalidInput(format!("receipt {run_id} was not found")))
    }

    pub fn rebuild_corpus_index(&mut self) -> Result<usize> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute("DELETE FROM corpus_index", [])?;
        let artifacts: Vec<RebuildArtifact> = {
            let mut statement = transaction.prepare(
                "SELECT d.document_id, COALESCE(d.title,''), d.normalized_url_identity, a.text_sha256, r.host_id, q.finished_at_utc, j.caller, j.lane, j.adapter \
                 FROM documents d \
                 JOIN normalized_artifacts a ON a.document_id=d.document_id \
                 JOIN responses r ON r.response_id=d.response_id \
                 JOIN requests q ON q.request_id=r.request_id \
                 JOIN crawl_jobs j ON j.job_id=q.job_id",
            )?;
            statement
                .query_map([], |row| {
                    Ok(RebuildArtifact {
                        document_id: row.get(0)?,
                        title: row.get(1)?,
                        text_hash: row.get(3)?,
                        host_id: row.get(4)?,
                        captured_at_utc: row.get(5)?,
                        caller: row.get(6)?,
                        lane: row.get(7)?,
                        adapter: row.get(8)?,
                    })
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        for artifact in &artifacts {
            let relative: String = transaction.query_row(
                "SELECT relative_path FROM blob_objects WHERE sha256=?1 AND availability_state='available-local'",
                [&artifact.text_hash],
                |row| row.get(0),
            )?;
            let body = fs::read_to_string(self.blobs.join(relative))?;
            transaction.execute(
                "INSERT INTO corpus_index(document_id,caller,lane,adapter,host_id,captured_at_utc,content_hash,index_schema_version,title,body) VALUES(?1,?2,?3,?4,?5,?6,?7,'1.0.0',?8,?9)",
                params![artifact.document_id, artifact.caller, artifact.lane, artifact.adapter, artifact.host_id, artifact.captured_at_utc, artifact.text_hash, artifact.title, body],
            )?;
        }
        transaction.commit()?;
        Ok(artifacts.len())
    }

    pub fn reconcile(&mut self) -> Result<ReconcileReport> {
        let temporary = self.blobs.join(".tmp");
        let mut removed_temporary_files = 0;
        for entry in fs::read_dir(&temporary)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                fs::remove_file(entry.path())?;
                removed_temporary_files += 1;
            }
        }
        let mut missing_blobs = 0;
        let records: Vec<(String, String)> = {
            let mut statement = self.connection.prepare(
                "SELECT sha256,relative_path FROM blob_objects WHERE availability_state='available-local'",
            )?;
            statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        for (sha256, relative) in &records {
            let path = self.blobs.join(relative);
            let valid = fs::read(&path)
                .ok()
                .is_some_and(|bytes| sha256_hex(&bytes) == *sha256);
            if !valid {
                missing_blobs += 1;
                self.connection.execute(
                    "UPDATE blob_objects SET availability_state='missing' WHERE sha256=?1",
                    [sha256],
                )?;
            }
        }
        let known_paths = records
            .iter()
            .map(|(_, relative)| PathBuf::from(relative))
            .collect::<std::collections::BTreeSet<_>>();
        let mut orphan_blobs = 0;
        for relative in collect_regular_paths(&self.blobs, &self.blobs)? {
            if !known_paths.contains(&relative) {
                let quarantine = self.root.join("recovery-orphans");
                create_private_directory(&quarantine)?;
                let file_name = relative.file_name().ok_or_else(|| {
                    CrawlError::Storage("orphan blob path has no filename".to_owned())
                })?;
                fs::rename(
                    self.blobs.join(&relative),
                    quarantine.join(format!(
                        "{}-{}",
                        Uuid::new_v4(),
                        file_name.to_string_lossy()
                    )),
                )?;
                orphan_blobs += 1;
            }
        }
        let unavailable_response_references = self.connection.execute(
            "UPDATE responses SET availability_state='missing' WHERE entity_body_sha256 IS NOT NULL AND NOT EXISTS (SELECT 1 FROM blob_objects b WHERE b.sha256=responses.entity_body_sha256 AND b.availability_state='available-local')",
            [],
        )?;
        let unavailable_artifact_references: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM normalized_artifacts a WHERE NOT EXISTS (SELECT 1 FROM blob_objects b WHERE b.sha256=a.markdown_sha256 AND b.availability_state='available-local') OR NOT EXISTS (SELECT 1 FROM blob_objects b WHERE b.sha256=a.text_sha256 AND b.availability_state='available-local')",
            [],
            |row| row.get(0),
        )?;
        let broken_references = unavailable_response_references
            .saturating_add(usize::try_from(unavailable_artifact_references).unwrap_or(usize::MAX));
        let stale_jobs: Vec<StaleJob> = {
            let mut statement = self.connection.prepare(
                "SELECT job_id,attempt_id,caller,source_surface,lane,execution_host,state FROM crawl_jobs WHERE state IN ('leased','running') AND lease_expires_at_utc < strftime('%Y-%m-%dT%H:%M:%fZ','now')",
            )?;
            statement
                .query_map([], |row| {
                    Ok(StaleJob {
                        job_id: row.get(0)?,
                        attempt_id: row.get(1)?,
                        caller: row.get(2)?,
                        source_surface: row.get(3)?,
                        lane: row.get(4)?,
                        execution_host: row.get(5)?,
                        prior_state: row.get(6)?,
                    })
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for job in &stale_jobs {
            transaction.execute(
                "UPDATE crawl_jobs SET state='pending',attempt_id=NULL,lease_owner=NULL,heartbeat_at_utc=NULL,lease_expires_at_utc=NULL,retry_eligible=1,terminal_result='recovered-expired-lease' WHERE job_id=?1",
                [&job.job_id],
            )?;
            transaction.execute(
                "INSERT INTO recovery_events(recovery_event_id,event_type,subject_id,prior_state,current_state,detail_json,created_at_utc) VALUES(?1,'expired-lease',?2,?3,'pending',?4,?5)",
                params![
                    Uuid::new_v4().to_string(),
                    job.job_id,
                    job.prior_state,
                    json!({"abandoned_attempt_id":job.attempt_id,"resumed_state":"pending"}).to_string(),
                    now_utc(),
                ],
            )?;
        }
        transaction.commit()?;
        for job in &stale_jobs {
            let mut receipt = base_receipt(
                Uuid::new_v4().to_string(),
                job.execution_host.clone(),
                job.caller.clone(),
                job.source_surface.clone(),
                job.lane.clone(),
                "startup-recovery".to_owned(),
            );
            "recovery".clone_into(&mut receipt.terminal_outcome);
            receipt.inspected_scope = json!({
                "job_id":job.job_id,
                "abandoned_attempt_id":job.attempt_id,
                "prior_state":job.prior_state,
                "current_state":"pending",
            });
            receipt.counts = json!({"abandoned_attempts":1,"resumed_jobs":1});
            self.write_receipt(&receipt)?;
        }
        Ok(ReconcileReport {
            removed_temporary_files,
            missing_blobs,
            orphan_blobs,
            broken_references,
            stale_leases: stale_jobs.len(),
        })
    }

    pub fn integrity(&self) -> Result<String> {
        self.connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .map_err(CrawlError::from)
    }

    pub fn backup_to(&self, destination: &Path) -> Result<BackupReport> {
        if destination.exists() {
            return Err(CrawlError::Refused(format!(
                "backup destination already exists: {}",
                destination.display()
            )));
        }
        create_private_directory(destination)?;
        let database_path = destination.join("state.sqlite3");
        self.connection.backup(MAIN_DB, &database_path, None)?;
        fs::set_permissions(&database_path, fs::Permissions::from_mode(0o600))?;

        let backup_blobs = destination.join("blobs");
        create_private_directory(&backup_blobs)?;
        let records: Vec<(String, String)> = {
            let mut statement = self.connection.prepare(
                "SELECT sha256,relative_path FROM blob_objects WHERE availability_state='available-local' ORDER BY sha256",
            )?;
            statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        for (sha256, relative_path) in &records {
            let source = self.blobs.join(relative_path);
            let bytes = fs::read(&source)?;
            if sha256_hex(&bytes) != *sha256 {
                return Err(CrawlError::Storage(format!(
                    "backup source blob {sha256} failed hash verification"
                )));
            }
            let target = backup_blobs.join(relative_path);
            atomic_private_write(&target, &bytes)?;
        }
        let backup_receipts = destination.join("compact-receipts");
        let compact_receipt_count = copy_regular_tree(&self.receipt_root, &backup_receipts)?;
        let manifest = json!({
            "schema_version":"1.0.0",
            "created_at_utc":now_utc(),
            "source_database":self.database,
            "database":"state.sqlite3",
            "blob_count":records.len(),
            "blobs":records.iter().map(|(sha256,path)|json!({"sha256":sha256,"relative_path":path})).collect::<Vec<_>>(),
            "compact_receipt_count":compact_receipt_count,
        });
        atomic_private_write(
            &destination.join("backup-manifest.json"),
            serde_json::to_vec_pretty(&manifest)?.as_slice(),
        )?;
        validate_backup(destination)
    }

    #[cfg(test)]
    pub(crate) const fn connection_for_tests(&self) -> &Connection {
        &self.connection
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CachedResponse {
    pub final_url: String,
    pub status: u16,
    pub selected_headers: Value,
    pub content_type: Option<String>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub entity_body_sha256: Option<String>,
    pub captured_at_utc: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedRobots {
    pub robots_url: String,
    pub status: Option<u16>,
    pub body_sha256: Option<String>,
    pub fetched_at_utc: String,
    pub expires_at_utc: String,
    pub decision_class: String,
    pub redacted_reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedFetch {
    pub job_id: String,
    pub request_id: String,
    pub response_id: String,
    pub document_id: Option<String>,
    pub manifest_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconcileReport {
    pub removed_temporary_files: usize,
    pub missing_blobs: usize,
    pub orphan_blobs: usize,
    pub broken_references: usize,
    pub stale_leases: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupReport {
    pub database_integrity: String,
    pub blob_count: usize,
    pub document_count: usize,
    pub receipt_count: usize,
    pub compact_receipt_count: usize,
    pub monitor_event_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThrottleReservation {
    pub wait_ms: u64,
    pub origin: String,
    pub destination_ip: String,
    pub usage_date_utc: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaReport {
    pub used_before_bytes: u64,
    pub used_after_bytes: u64,
    pub reserved_bytes: u64,
    pub evicted_blobs: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StaleJob {
    job_id: String,
    attempt_id: Option<String>,
    caller: String,
    source_surface: String,
    lane: String,
    execution_host: String,
    prior_state: String,
}

#[must_use]
pub fn base_receipt(
    run_id: String,
    host_id: String,
    caller: String,
    source_surface: String,
    lane: String,
    command: String,
) -> Receipt {
    Receipt {
        receipt_schema_version: "1.0.0".to_owned(),
        producer_version: PRODUCER_VERSION.to_owned(),
        run_id,
        parent_run_id: None,
        host_id,
        caller,
        source_surface,
        lane,
        command,
        inspected_scope: json!({}),
        terminal_outcome: "failed".to_owned(),
        counts: json!({}),
        budget_outcome: "within-budget".to_owned(),
        monotonic_duration_ms: 0,
        artifact_paths: Vec::new(),
        source_hashes: Vec::new(),
        error_summary: None,
        software_version: PRODUCER_VERSION.to_owned(),
        normalization_policy_version: "1.0.0".to_owned(),
        policy_hash: sha256_hex(b"phase1-default"),
        configuration_hash: sha256_hex(b"phase1-default"),
        seed_manifest_hash: sha256_hex(b"single-url"),
        created_at_utc: now_utc(),
    }
}

fn create_private_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn atomic_private_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| CrawlError::Storage("output path has no parent".to_owned()))?;
    create_private_directory(parent)?;
    let temporary = parent.join(format!(".{}.tmp", Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn copy_regular_tree(source: &Path, destination: &Path) -> Result<usize> {
    if !source.exists() {
        create_private_directory(destination)?;
        return Ok(0);
    }
    create_private_directory(destination)?;
    let mut copied = 0;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let target = destination.join(entry.file_name());
        if file_type.is_dir() {
            copied += copy_regular_tree(&entry.path(), &target)?;
        } else if file_type.is_file() {
            atomic_private_write(&target, &fs::read(entry.path())?)?;
            copied += 1;
        } else {
            return Err(CrawlError::Refused(format!(
                "backup refuses non-regular path {}",
                entry.path().display()
            )));
        }
    }
    Ok(copied)
}

fn collect_regular_paths(root: &Path, current: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            if entry.file_name() != ".tmp" {
                paths.extend(collect_regular_paths(root, &entry.path())?);
            }
        } else if file_type.is_file() {
            paths.push(
                entry
                    .path()
                    .strip_prefix(root)
                    .map_err(|error| CrawlError::Storage(error.to_string()))?
                    .to_path_buf(),
            );
        } else {
            return Err(CrawlError::Refused(format!(
                "blob recovery refuses non-regular path {}",
                entry.path().display()
            )));
        }
    }
    Ok(paths)
}

#[allow(clippy::too_many_arguments)]
fn reserve_throttle_scope(
    transaction: &rusqlite::Transaction<'_>,
    scope_type: &str,
    scope_value: &str,
    usage_date: &str,
    now_text: &str,
    now: DateTime<Utc>,
    minimum_delay_ms: u64,
    daily_cap: u64,
) -> Result<u64> {
    let existing: Option<(i64, String)> = transaction
        .query_row(
            "SELECT request_count,last_request_at_utc FROM request_throttles WHERE scope_type=?1 AND scope_value=?2 AND usage_date_utc=?3",
            params![scope_type, scope_value, usage_date],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let wait_ms = if let Some((request_count, last_request)) = existing {
        if u64::try_from(request_count).unwrap_or(u64::MAX) >= daily_cap {
            return Err(CrawlError::Refused(format!(
                "{scope_type} daily request cap {daily_cap} reached"
            )));
        }
        let last = DateTime::parse_from_rfc3339(&last_request)
            .map_err(|error| CrawlError::Storage(format!("invalid throttle timestamp: {error}")))?
            .with_timezone(&Utc);
        let elapsed = now.signed_duration_since(last).num_milliseconds().max(0);
        minimum_delay_ms.saturating_sub(u64::try_from(elapsed).unwrap_or(0))
    } else {
        0
    };
    transaction.execute(
        "INSERT INTO request_throttles(scope_type,scope_value,usage_date_utc,request_count,byte_count,last_request_at_utc) VALUES(?1,?2,?3,1,0,?4) ON CONFLICT(scope_type,scope_value,usage_date_utc) DO UPDATE SET request_count=request_count+1,last_request_at_utc=excluded.last_request_at_utc",
        params![scope_type, scope_value, usage_date, now_text],
    )?;
    Ok(wait_ms)
}

pub fn validate_backup(root: &Path) -> Result<BackupReport> {
    let manifest: Value = serde_json::from_slice(&fs::read(root.join("backup-manifest.json"))?)?;
    let connection = Connection::open(root.join("state.sqlite3"))?;
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(CrawlError::Storage(format!(
            "backup database integrity failed: {integrity}"
        )));
    }
    let blobs = manifest
        .get("blobs")
        .and_then(Value::as_array)
        .ok_or_else(|| CrawlError::Storage("backup manifest lacks blobs".to_owned()))?;
    for blob in blobs {
        let sha256 = blob
            .get("sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| CrawlError::Storage("backup blob lacks sha256".to_owned()))?;
        let relative = blob
            .get("relative_path")
            .and_then(Value::as_str)
            .ok_or_else(|| CrawlError::Storage("backup blob lacks relative path".to_owned()))?;
        let bytes = fs::read(root.join("blobs").join(relative))?;
        if sha256_hex(&bytes) != sha256 {
            return Err(CrawlError::Storage(format!(
                "backup blob {sha256} failed validation"
            )));
        }
    }
    let document_count = table_count(&connection, "documents")?;
    let receipt_count = table_count(&connection, "receipts")?;
    let monitor_event_count = table_count(&connection, "monitor_events")?;
    let compact_receipt_count = manifest
        .get("compact_receipt_count")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| CrawlError::Storage("invalid compact receipt count".to_owned()))?;
    Ok(BackupReport {
        database_integrity: integrity,
        blob_count: blobs.len(),
        document_count,
        receipt_count,
        compact_receipt_count,
        monitor_event_count,
    })
}

fn table_count(connection: &Connection, table: &str) -> Result<usize> {
    if !matches!(table, "documents" | "receipts" | "monitor_events") {
        return Err(CrawlError::InvalidInput(
            "unsupported count table".to_owned(),
        ));
    }
    let count: i64 = connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        row.get(0)
    })?;
    usize::try_from(count).map_err(|_| CrawlError::Storage("negative table count".to_owned()))
}

fn now_utc() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[must_use]
pub fn lane_name(lane: &Lane) -> &str {
    lane.as_str()
}

#[must_use]
pub const fn surface_name(surface: SourceSurface) -> &'static str {
    match surface {
        SourceSurface::Cli => "cli",
        SourceSurface::ScheduledWrapper => "scheduled-wrapper",
        SourceSurface::McpReadOnly => "mcp-read-only",
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{StateStore, base_receipt};

    fn temporary_root(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("vault-crawl-store-{name}-{}", uuid::Uuid::new_v4()))
    }

    #[test]
    fn compact_receipt_failure_uses_state_local_emergency_path() {
        let root = temporary_root("receipt-fallback");
        let receipt_root = root.join("compact");
        let mut store = StateStore::open(&root, &receipt_root).expect("store");
        fs::remove_dir(&receipt_root).expect("remove empty receipt root");
        fs::write(&receipt_root, b"blocked-directory").expect("replace root with file");
        let receipt = base_receipt(
            uuid::Uuid::new_v4().to_string(),
            "test-host".to_owned(),
            "phase1-test".to_owned(),
            "cli".to_owned(),
            "build".to_owned(),
            "receipt-fallback-test".to_owned(),
        );
        let path = store.write_receipt(&receipt).expect("emergency receipt");
        assert!(path.starts_with(root.join("emergency-receipts")));
        assert!(path.is_file());
        let delivery: String = store
            .connection_for_tests()
            .query_row(
                "SELECT delivery_state FROM receipts WHERE run_id=?1",
                [&receipt.run_id],
                |row| row.get(0),
            )
            .expect("receipt delivery state");
        assert_eq!(delivery, "compact-fallback");
        drop(store);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn corrupt_database_is_refused_before_migration_or_work() {
        let root = temporary_root("corrupt-database");
        fs::create_dir_all(&root).expect("corrupt database root");
        fs::write(root.join("state.sqlite3"), b"not a sqlite database")
            .expect("corrupt database bytes");
        let error = StateStore::open(&root, &root.join("receipts"))
            .expect_err("corrupt database must fail");
        assert!(error.to_string().contains("database"));
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn blob_store_deduplicates_and_verifies() {
        let root = temporary_root("blob");
        let receipts = root.join("receipts");
        let mut store = StateStore::open(&root, &receipts).expect("open store");
        let first = store
            .store_blob(b"evidence", "entity", "standard", false)
            .expect("store first");
        let second = store
            .store_blob(b"evidence", "entity", "standard", false)
            .expect("store second");
        assert_eq!(first.sha256, second.sha256);
        assert_eq!(
            store.read_blob(&first.sha256).expect("read blob"),
            b"evidence"
        );
        drop(store);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn reconcile_handles_partial_corrupt_and_orphan_blob_state() {
        let root = temporary_root("reconcile");
        let receipts = root.join("receipts");
        let mut store = StateStore::open(&root, &receipts).expect("open store");
        fs::write(root.join("blobs/.tmp/orphan.tmp"), b"partial").expect("write orphan");
        let blob = store
            .store_blob(b"known-good", "entity", "standard", false)
            .expect("store known blob");
        fs::write(root.join("blobs").join(&blob.relative_path), b"truncated")
            .expect("corrupt known blob");
        fs::create_dir_all(root.join("blobs/ff")).expect("orphan directory");
        fs::write(root.join("blobs/ff/unreferenced"), b"orphan evidence").expect("orphan evidence");
        let report = store.reconcile().expect("reconcile");
        assert_eq!(report.removed_temporary_files, 1);
        assert_eq!(report.missing_blobs, 1);
        assert_eq!(report.orphan_blobs, 1);
        let availability: String = store
            .connection_for_tests()
            .query_row(
                "SELECT availability_state FROM blob_objects WHERE sha256=?1",
                [&blob.sha256],
                |row| row.get(0),
            )
            .expect("corrupt blob state");
        assert_eq!(availability, "missing");
        assert_eq!(
            fs::read_dir(root.join("recovery-orphans"))
                .expect("quarantine")
                .count(),
            1
        );
        drop(store);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn persisted_origin_and_ip_throttles_enforce_delay_and_daily_caps() {
        let root = temporary_root("throttle");
        let receipts = root.join("receipts");
        let mut store = StateStore::open(&root, &receipts).expect("open store");
        let first = store
            .reserve_request("https://example.com:443", "fixture-address", 500, 2, 2)
            .expect("first reservation");
        assert_eq!(first.wait_ms, 0);
        store
            .record_response_bytes(&first, 128)
            .expect("record bytes");
        let second = store
            .reserve_request("https://example.com:443", "fixture-address", 500, 2, 2)
            .expect("second reservation");
        assert!(second.wait_ms > 0);
        let refused =
            store.reserve_request("https://example.com:443", "fixture-address", 500, 2, 2);
        assert!(matches!(refused, Err(crate::error::CrawlError::Refused(_))));
        drop(store);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn quota_eviction_removes_only_unreferenced_unpinned_blobs() {
        let root = temporary_root("quota");
        let receipts = root.join("receipts");
        let mut store = StateStore::open(&root, &receipts).expect("open store");
        let evictable = store
            .store_blob(b"0123456789", "entity", "cache", false)
            .expect("store evictable");
        let held = store
            .store_blob(b"pinned", "text", "evidence", true)
            .expect("store held");
        let report = store.enforce_storage_quota(11, 5).expect("enforce quota");
        assert_eq!(report.evicted_blobs, 1);
        assert!(store.read_blob(&evictable.sha256).is_err());
        assert_eq!(store.read_blob(&held.sha256).expect("held blob"), b"pinned");
        let refusal = store.enforce_storage_quota(10, 5);
        assert!(matches!(refusal, Err(crate::error::CrawlError::Refused(_))));
        drop(store);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn streaming_limit_refusal_removes_partial_temporary_evidence() {
        let root = temporary_root("stream-limit");
        let receipts = root.join("receipts");
        let mut store = StateStore::open(&root, &receipts).expect("open store");
        let result = store.store_blob_reader(
            std::io::Cursor::new(b"too-large"),
            3,
            "entity",
            "standard",
            false,
        );
        assert!(matches!(result, Err(crate::error::CrawlError::Refused(_))));
        assert_eq!(
            fs::read_dir(root.join("blobs/.tmp"))
                .expect("temp dir")
                .count(),
            0
        );
        let blob_count: i64 = store
            .connection_for_tests()
            .query_row("SELECT COUNT(*) FROM blob_objects", [], |row| row.get(0))
            .expect("blob count");
        assert_eq!(blob_count, 0);
        drop(store);
        fs::remove_dir_all(root).expect("cleanup");
    }
}
