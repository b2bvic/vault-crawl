#![allow(clippy::missing_errors_doc, clippy::too_many_lines)]

use std::collections::BTreeSet;
use std::io::{Cursor, Read};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use reqwest::StatusCode;
use reqwest::blocking::Client;
use reqwest::header::{
    CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, ETAG, HeaderMap, HeaderValue,
    IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, LOCATION, USER_AGENT,
};
use robotstxt::DefaultMatcher;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;
use uuid::Uuid;

use crate::contract::{Lane, SourceSurface};
use crate::error::{CrawlError, Result};
use crate::extract::{ExtractedDocument, extract};
use crate::hash::sha256_hex;
use crate::policy::{
    ApprovedDestination, NetworkProfile, NormalizedUrl, connected_peer_is_approved,
    normalize_url_for_profile, redacted_url, refuse_ambient_proxies, resolve_destination,
    same_origin,
};
use crate::store::{
    BlobRecord, PersistInput, RedirectRecord, StateStore, ThrottleReservation, base_receipt,
    lane_name, surface_name,
};

pub const USER_AGENT_VALUE: &str = "vault-crawl/0.1 (+https://github.com/b2bvic/vault-crawl)";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchPolicy {
    pub max_redirects: usize,
    pub max_body_bytes: usize,
    pub max_compressed_body_bytes: usize,
    pub request_timeout_ms: u64,
    pub connect_timeout_ms: u64,
    pub robots_max_bytes: usize,
    pub robots_cache_ttl_seconds: u64,
    pub respect_robots: bool,
    pub network_profile: String,
    pub minimum_origin_delay_ms: u64,
    pub max_origin_requests_per_day: u64,
    pub max_destination_ip_requests_per_day: u64,
    pub max_attempts: usize,
    pub base_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub max_store_bytes: u64,
    pub metadata_reserve_bytes: u64,
}

impl Default for FetchPolicy {
    fn default() -> Self {
        Self {
            max_redirects: 5,
            max_body_bytes: 10 * 1024 * 1024,
            max_compressed_body_bytes: 10 * 1024 * 1024,
            request_timeout_ms: 30_000,
            connect_timeout_ms: 10_000,
            robots_max_bytes: 512 * 1024,
            robots_cache_ttl_seconds: 3_600,
            respect_robots: true,
            network_profile: "automatic-public".to_owned(),
            minimum_origin_delay_ms: 250,
            max_origin_requests_per_day: 1_000,
            max_destination_ip_requests_per_day: 2_500,
            max_attempts: 3,
            base_backoff_ms: 250,
            max_backoff_ms: 5_000,
            max_store_bytes: 5 * 1024 * 1024 * 1024,
            metadata_reserve_bytes: 10 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchContext {
    pub caller: String,
    pub lane: Lane,
    pub source_surface: SourceSurface,
    pub host_id: String,
    pub command: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FetchOutput {
    pub run_id: String,
    pub job_id: String,
    pub request_id: String,
    pub response_id: String,
    pub document_id: Option<String>,
    pub original_url: String,
    pub normalized_url: String,
    pub final_url: String,
    pub status: u16,
    pub content_type: String,
    pub entity_body_sha256: String,
    pub byte_count: usize,
    pub compressed_byte_count: usize,
    pub cache_outcome: String,
    pub render_state: String,
    pub receipt_path: String,
    pub artifact_manifest_path: Option<String>,
    pub document: Option<ExtractedDocument>,
    pub redirect_count: usize,
    pub robots_source: String,
    pub robots_url: String,
    pub robots_status: Option<u16>,
    pub robots_selected_group: String,
    pub robots_cache_age_seconds: Option<u64>,
}

#[derive(Debug)]
struct NetworkResponse {
    destination: ApprovedDestination,
    final_url: Url,
    status: StatusCode,
    headers: Value,
    raw_headers: HeaderMap,
    body: Vec<u8>,
    compressed_byte_count: usize,
    body_blob: Option<BlobRecord>,
    redirects: Vec<RedirectRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RobotsDecision {
    allowed: bool,
    decision: String,
    reason: String,
    crawl_delay_ms: u64,
    source: String,
    source_url: String,
    status: Option<u16>,
    selected_group: String,
    cache_age_seconds: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CancellationStage {
    Dns,
    Body,
    Parse,
}

struct TransportResponse {
    status: StatusCode,
    headers: HeaderMap,
    peer: SocketAddr,
    body: Box<dyn Read + Send>,
}

trait FetchRuntime {
    fn check_cancelled(&self, _stage: CancellationStage) -> Result<()> {
        Ok(())
    }

    fn resolve(&self, url: &Url, profile: NetworkProfile) -> Result<ApprovedDestination>;

    fn send(
        &self,
        destination: &ApprovedDestination,
        url: &Url,
        headers: &HeaderMap,
        policy: &FetchPolicy,
    ) -> Result<TransportResponse>;
}

struct ProductionRuntime;

impl FetchRuntime for ProductionRuntime {
    fn resolve(&self, url: &Url, profile: NetworkProfile) -> Result<ApprovedDestination> {
        resolve_destination(url, profile)
    }

    fn send(
        &self,
        destination: &ApprovedDestination,
        url: &Url,
        headers: &HeaderMap,
        policy: &FetchPolicy,
    ) -> Result<TransportResponse> {
        let client = pinned_client(destination, policy)?;
        let response = client
            .get(url.clone())
            .headers(headers.clone())
            .send()
            .map_err(|error| CrawlError::Network(redact_error(&error.to_string())))?;
        let peer = response.remote_addr().ok_or_else(|| {
            CrawlError::Refused("HTTP transport did not expose the connected peer".to_owned())
        })?;
        Ok(TransportResponse {
            status: response.status(),
            headers: response.headers().clone(),
            peer,
            body: Box::new(response),
        })
    }
}

pub fn fetch_and_store(
    store: &mut StateStore,
    input_url: &str,
    policy: &FetchPolicy,
    context: &FetchContext,
) -> Result<FetchOutput> {
    fetch_and_store_with_runtime(store, input_url, policy, context, &ProductionRuntime)
}

fn fetch_and_store_with_runtime(
    store: &mut StateStore,
    input_url: &str,
    policy: &FetchPolicy,
    context: &FetchContext,
    runtime: &dyn FetchRuntime,
) -> Result<FetchOutput> {
    let run_id = Uuid::new_v4().to_string();
    let started = Instant::now();
    let mut receipt = base_receipt(
        run_id.clone(),
        context.host_id.clone(),
        context.caller.clone(),
        surface_name(context.source_surface).to_owned(),
        lane_name(&context.lane).to_owned(),
        context.command.clone(),
    );
    receipt.inspected_scope = json!({
        "input_url": Url::parse(input_url).map_or_else(
            |_| "[INVALID-URL]".to_owned(),
            |url| redacted_url(&url)
        )
    });

    let result = (|| {
        let network_profile = parse_network_profile(policy)?;
        let normalized = normalize_url_for_profile(input_url, network_profile)?;
        fetch_and_store_inner(
            store,
            &run_id,
            &normalized,
            policy,
            context,
            started,
            runtime,
        )
    })();
    match result {
        Ok(mut output) => {
            "success".clone_into(&mut receipt.terminal_outcome);
            receipt.inspected_scope = json!({
                "urls":[output.normalized_url],
                "robots":{
                    "source":output.robots_source,
                    "url":output.robots_url,
                    "status":output.robots_status,
                    "selected_group":output.robots_selected_group,
                    "cache_age_seconds":output.robots_cache_age_seconds,
                }
            });
            receipt.counts = json!({"requests":output.redirect_count+1,"redirects":output.redirect_count,"documents":usize::from(output.document_id.is_some()),"compressed_bytes":output.compressed_byte_count,"expanded_bytes":output.byte_count,"cache_hits":usize::from(output.cache_outcome != "miss")});
            receipt.monotonic_duration_ms = elapsed_millis(started);
            receipt
                .source_hashes
                .push(output.entity_body_sha256.clone());
            if let Some(path) = &output.artifact_manifest_path {
                receipt.artifact_paths.push(path.clone());
            }
            let receipt_path = store.write_receipt(&receipt)?;
            output.receipt_path = receipt_path.display().to_string();
            Ok(output)
        }
        Err(error) => {
            receipt.monotonic_duration_ms = elapsed_millis(started);
            receipt.error_summary = Some(redact_error(&error.to_string()));
            receipt.terminal_outcome = if matches!(error, CrawlError::Refused(_)) {
                "refused".to_owned()
            } else {
                "failed".to_owned()
            };
            receipt.counts = json!({"requests":0,"documents":0,"bytes":0});
            let receipt_path = store.write_receipt(&receipt)?;
            Err(CrawlError::Terminal {
                outcome: receipt.terminal_outcome,
                message: error.to_string(),
                receipt_path: receipt_path.display().to_string(),
            })
        }
    }
}

fn fetch_and_store_inner(
    store: &mut StateStore,
    run_id: &str,
    normalized: &NormalizedUrl,
    policy: &FetchPolicy,
    context: &FetchContext,
    started: Instant,
    runtime: &dyn FetchRuntime,
) -> Result<FetchOutput> {
    refuse_ambient_proxies()?;
    store.enforce_storage_quota(
        policy.max_store_bytes,
        u64::try_from(policy.max_body_bytes)
            .unwrap_or(u64::MAX)
            .saturating_add(policy.metadata_reserve_bytes),
    )?;
    let network_profile = parse_network_profile(policy)?;
    let robots = if policy.respect_robots {
        check_robots(
            store,
            &normalized.normalized,
            policy,
            network_profile,
            runtime,
        )?
    } else {
        return Err(CrawlError::Refused(
            "robots override is unavailable through the Phase 1 fetch path".to_owned(),
        ));
    };
    if !robots.allowed {
        return Err(CrawlError::Refused(format!(
            "robots policy: {}",
            robots.reason
        )));
    }

    let cached = store.cache_entry(normalized.normalized.as_str())?;
    let mut conditional_headers = HeaderMap::new();
    if let Some(cache) = &cached {
        if let Some(etag) = &cache.etag
            && let Ok(value) = HeaderValue::from_str(etag)
        {
            conditional_headers.insert(IF_NONE_MATCH, value);
        }
        if let Some(last_modified) = &cache.last_modified
            && let Ok(value) = HeaderValue::from_str(last_modified)
        {
            conditional_headers.insert(IF_MODIFIED_SINCE, value);
        }
    }

    let response = request_with_redirects(
        store,
        normalized.clone(),
        conditional_headers,
        policy.max_body_bytes,
        policy,
        network_profile,
        policy.minimum_origin_delay_ms.max(robots.crawl_delay_ms),
        true,
        runtime,
    )?;
    let (
        status,
        final_url,
        selected_headers,
        raw_headers,
        body,
        compressed_byte_count,
        cache_outcome,
        streamed_entity,
    ) = if response.status == StatusCode::NOT_MODIFIED {
        let cache = cached.ok_or_else(|| {
            CrawlError::Storage("received 304 without a cached entity".to_owned())
        })?;
        let sha = cache
            .entity_body_sha256
            .ok_or_else(|| CrawlError::Storage("cached response has no entity hash".to_owned()))?;
        (
            StatusCode::from_u16(cache.status)
                .map_err(|error| CrawlError::Storage(error.to_string()))?,
            Url::parse(&cache.final_url).map_err(|error| CrawlError::Storage(error.to_string()))?,
            cache.selected_headers,
            response.raw_headers,
            store.read_blob(&sha)?,
            response.compressed_byte_count,
            "revalidated-304",
            None,
        )
    } else {
        (
            response.status,
            response.final_url.clone(),
            response.headers.clone(),
            response.raw_headers.clone(),
            response.body.clone(),
            response.compressed_byte_count,
            "miss",
            response.body_blob.clone(),
        )
    };
    if !status.is_success() {
        return Err(CrawlError::Network(format!(
            "HTTP status {} for {}",
            status.as_u16(),
            redacted_url(&final_url)
        )));
    }
    let content_type = raw_headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .or_else(|| {
            selected_headers
                .get("content-type")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "application/octet-stream".to_owned());
    let entity = match streamed_entity {
        Some(entity) => entity,
        None => store.store_blob(&body, "entity", "standard", false)?,
    };
    runtime.check_cancelled(CancellationStage::Parse)?;
    let document = match extract(&body, &content_type, &final_url) {
        Ok(document) => Some(document),
        Err(CrawlError::Parser(message)) if message.starts_with("unsupported media type ") => None,
        Err(error) => return Err(error),
    };
    let markdown_blob = document
        .as_ref()
        .map(|value| {
            store.store_blob(
                value.primary_markdown.as_bytes(),
                "markdown",
                "standard",
                true,
            )
        })
        .transpose()?;
    let text_blob = document
        .as_ref()
        .map(|value| store.store_blob(value.primary_text.as_bytes(), "text", "standard", true))
        .transpose()?;
    let etag = raw_headers.get(ETAG).and_then(|value| value.to_str().ok());
    let last_modified = raw_headers
        .get(LAST_MODIFIED)
        .and_then(|value| value.to_str().ok());
    let idempotency_key = sha256_hex(
        format!(
            "static-http:v1:{}:{}:{}:{}:{}",
            context.caller,
            lane_name(&context.lane),
            context.command,
            normalized.normalized,
            sha256_hex(&serde_json::to_vec(policy)?)
        )
        .as_bytes(),
    );
    let persisted = store.persist_fetch(&PersistInput {
        run_id,
        idempotency_key: &idempotency_key,
        caller: &context.caller,
        lane: context.lane.clone(),
        source_surface: context.source_surface,
        host_id: &context.host_id,
        command: &context.command,
        normalized,
        destination: &response.destination,
        status: status.as_u16(),
        final_url: final_url.as_str(),
        selected_headers: &selected_headers,
        content_type: &content_type,
        etag,
        last_modified,
        entity: &entity,
        document: document.as_ref(),
        markdown_blob: markdown_blob.as_ref(),
        text_blob: text_blob.as_ref(),
        elapsed_ms: elapsed_millis(started),
        cache_outcome,
        robots_decision: &robots.decision,
        robots_reason: &robots.reason,
        redirects: &response.redirects,
    })?;
    Ok(FetchOutput {
        run_id: run_id.to_owned(),
        job_id: persisted.job_id,
        request_id: persisted.request_id,
        response_id: persisted.response_id,
        document_id: persisted.document_id,
        original_url: normalized.original.clone(),
        normalized_url: normalized.normalized.to_string(),
        final_url: final_url.to_string(),
        status: status.as_u16(),
        content_type,
        entity_body_sha256: entity.sha256,
        byte_count: body.len(),
        compressed_byte_count,
        cache_outcome: cache_outcome.to_owned(),
        render_state: if document.as_ref().is_some_and(|value| value.needs_render) {
            "needs-render".to_owned()
        } else {
            "not-needed".to_owned()
        },
        receipt_path: String::new(),
        artifact_manifest_path: persisted
            .manifest_path
            .map(|path| path.display().to_string()),
        document,
        redirect_count: response.redirects.len(),
        robots_source: robots.source,
        robots_url: robots.source_url,
        robots_status: robots.status,
        robots_selected_group: robots.selected_group,
        robots_cache_age_seconds: robots.cache_age_seconds,
    })
}

fn check_robots(
    store: &mut StateStore,
    target: &Url,
    policy: &FetchPolicy,
    profile: NetworkProfile,
    runtime: &dyn FetchRuntime,
) -> Result<RobotsDecision> {
    let target_origin = crate::policy::origin(target);
    if let Some((cached, fresh)) = store.robots_entry_with_freshness(&target_origin)? {
        let cache_age_seconds = DateTime::parse_from_rfc3339(&cached.fetched_at_utc)
            .ok()
            .and_then(|fetched| {
                u64::try_from(
                    Utc::now()
                        .signed_duration_since(fetched.with_timezone(&Utc))
                        .num_seconds(),
                )
                .ok()
            });
        if !fresh && cached.decision_class == "deny" {
            return Ok(RobotsDecision {
                allowed: false,
                decision: "refused".to_owned(),
                reason: format!("stale robots deny retained: {}", cached.redacted_reason),
                crawl_delay_ms: 0,
                source: "stale-cache-deny".to_owned(),
                source_url: cached.robots_url,
                status: cached.status,
                selected_group: "none".to_owned(),
                cache_age_seconds,
            });
        }
        if fresh {
            return match cached.decision_class.as_str() {
                "rules" => {
                    let sha256 = cached.body_sha256.ok_or_else(|| {
                        CrawlError::Storage("robots rules cache entry has no body hash".to_owned())
                    })?;
                    let bytes = store.read_blob(&sha256)?;
                    let text = String::from_utf8(bytes).map_err(|_| {
                        CrawlError::Refused("cached robots body is not valid UTF-8".to_owned())
                    })?;
                    let mut decision = robots_rules_decision(
                        &text,
                        target,
                        "fresh robots cache",
                        &cached.robots_url,
                        cached.status,
                    );
                    decision.cache_age_seconds = cache_age_seconds;
                    Ok(decision)
                }
                "absent" => Ok(RobotsDecision {
                    allowed: true,
                    decision: "allowed".to_owned(),
                    reason: format!("fresh robots cache: {}", cached.redacted_reason),
                    crawl_delay_ms: 0,
                    source: "fresh-cache-absent".to_owned(),
                    source_url: cached.robots_url,
                    status: cached.status,
                    selected_group: "none".to_owned(),
                    cache_age_seconds,
                }),
                "deny" => Ok(RobotsDecision {
                    allowed: false,
                    decision: "refused".to_owned(),
                    reason: format!("fresh robots cache: {}", cached.redacted_reason),
                    crawl_delay_ms: 0,
                    source: "fresh-cache-deny".to_owned(),
                    source_url: cached.robots_url,
                    status: cached.status,
                    selected_group: "none".to_owned(),
                    cache_age_seconds,
                }),
                value => Err(CrawlError::Storage(format!(
                    "invalid robots cache decision class {value}"
                ))),
            };
        }
    }
    let mut robots_url = target.clone();
    robots_url.set_path("/robots.txt");
    robots_url.set_query(None);
    robots_url.set_fragment(None);
    let normalized = normalize_url_for_profile(robots_url.as_str(), profile)?;
    let response = request_with_redirects(
        store,
        normalized,
        HeaderMap::new(),
        policy.robots_max_bytes,
        policy,
        profile,
        policy.minimum_origin_delay_ms,
        false,
        runtime,
    );
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            return Ok(RobotsDecision {
                allowed: false,
                decision: "refused".to_owned(),
                reason: format!(
                    "robots retrieval failed: {}",
                    redact_error(&error.to_string())
                ),
                crawl_delay_ms: 0,
                source: "network-error".to_owned(),
                source_url: robots_url.to_string(),
                status: None,
                selected_group: "none".to_owned(),
                cache_age_seconds: None,
            });
        }
    };
    match response.status.as_u16() {
        200 => {
            let body = store.store_blob(&response.body, "entity", "robots", true)?;
            let Ok(robots) = String::from_utf8(response.body.clone()) else {
                let reason = "robots body is not valid UTF-8";
                store.cache_robots(
                    &target_origin,
                    response.final_url.as_str(),
                    Some(200),
                    Some(&body.sha256),
                    policy.robots_cache_ttl_seconds.min(300),
                    "deny",
                    reason,
                )?;
                return Ok(RobotsDecision {
                    allowed: false,
                    decision: "refused".to_owned(),
                    reason: reason.to_owned(),
                    crawl_delay_ms: 0,
                    source: "network-parse-deny".to_owned(),
                    source_url: response.final_url.to_string(),
                    status: Some(200),
                    selected_group: "none".to_owned(),
                    cache_age_seconds: None,
                });
            };
            store.cache_robots(
                &target_origin,
                response.final_url.as_str(),
                Some(200),
                Some(&body.sha256),
                policy.robots_cache_ttl_seconds,
                "rules",
                "robots rules fetched successfully",
            )?;
            Ok(robots_rules_decision(
                &robots,
                target,
                "network robots fetch",
                response.final_url.as_str(),
                Some(200),
            ))
        }
        404 | 410 => {
            let reason = format!(
                "robots file absent with status {}",
                response.status.as_u16()
            );
            store.cache_robots(
                &target_origin,
                robots_url.as_str(),
                Some(response.status.as_u16()),
                None,
                policy.robots_cache_ttl_seconds,
                "absent",
                &reason,
            )?;
            Ok(RobotsDecision {
                allowed: true,
                decision: "allowed".to_owned(),
                reason,
                crawl_delay_ms: 0,
                source: "network-absent".to_owned(),
                source_url: response.final_url.to_string(),
                status: Some(response.status.as_u16()),
                selected_group: "none".to_owned(),
                cache_age_seconds: None,
            })
        }
        status => {
            let reason = format!("robots status {status} fails closed");
            store.cache_robots(
                &target_origin,
                robots_url.as_str(),
                Some(status),
                None,
                policy.robots_cache_ttl_seconds.min(300),
                "deny",
                &reason,
            )?;
            Ok(RobotsDecision {
                allowed: false,
                decision: "refused".to_owned(),
                reason,
                crawl_delay_ms: 0,
                source: "network-status-deny".to_owned(),
                source_url: response.final_url.to_string(),
                status: Some(status),
                selected_group: "none".to_owned(),
                cache_age_seconds: None,
            })
        }
    }
}

fn robots_rules_decision(
    robots: &str,
    target: &Url,
    source: &str,
    source_url: &str,
    status: Option<u16>,
) -> RobotsDecision {
    let mut matcher = DefaultMatcher::default();
    let allowed = matcher.one_agent_allowed_by_robots(robots, "VaultCrawl", target.as_str());
    RobotsDecision {
        allowed,
        decision: if allowed { "allowed" } else { "refused" }.to_owned(),
        reason: if allowed {
            format!("{source}: matching user-agent group allows target")
        } else {
            format!("{source}: matching user-agent group disallows target")
        },
        crawl_delay_ms: parse_crawl_delay_ms(robots, "VaultCrawl"),
        source: source.to_owned(),
        source_url: source_url.to_owned(),
        status,
        selected_group: selected_robots_group(robots),
        cache_age_seconds: None,
    }
}

fn selected_robots_group(robots: &str) -> String {
    let agents = robots.lines().filter_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("user-agent")
            .then(|| value.trim().to_owned())
    });
    let mut fallback = None;
    for agent in agents {
        if agent.eq_ignore_ascii_case("VaultCrawl") {
            return agent;
        }
        if agent == "*" {
            fallback = Some(agent);
        }
    }
    fallback.unwrap_or_else(|| "none".to_owned())
}

#[allow(clippy::too_many_arguments)]
fn request_with_redirects(
    store: &mut StateStore,
    initial: NormalizedUrl,
    mut headers: HeaderMap,
    max_body_bytes: usize,
    policy: &FetchPolicy,
    profile: NetworkProfile,
    minimum_delay_ms: u64,
    enforce_redirect_robots: bool,
    runtime: &dyn FetchRuntime,
) -> Result<NetworkResponse> {
    let mut current = initial;
    let mut visited = BTreeSet::new();
    let mut redirects = Vec::new();
    for redirect_count in 0..=policy.max_redirects {
        if !visited.insert(current.normalized.to_string()) {
            return Err(CrawlError::Refused("redirect loop detected".to_owned()));
        }
        headers.insert(USER_AGENT, HeaderValue::from_static(USER_AGENT_VALUE));
        let (response, destination, reservation) = request_current_with_retries(
            store,
            &current.normalized,
            &headers,
            policy,
            profile,
            minimum_delay_ms,
            runtime,
        )?;
        let status = response.status;
        if matches!(
            status,
            StatusCode::MOVED_PERMANENTLY
                | StatusCode::FOUND
                | StatusCode::SEE_OTHER
                | StatusCode::TEMPORARY_REDIRECT
                | StatusCode::PERMANENT_REDIRECT
        ) {
            if redirect_count == policy.max_redirects {
                return Err(CrawlError::Refused(format!(
                    "redirect cap {} exceeded",
                    policy.max_redirects
                )));
            }
            let location = response
                .headers
                .get(LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| CrawlError::Network("redirect missing Location".to_owned()))?;
            let next = current
                .normalized
                .join(location)
                .map_err(|error| CrawlError::Network(format!("invalid redirect: {error}")))?;
            let next = normalize_url_for_profile(next.as_str(), profile)?;
            let redirect_robots = if enforce_redirect_robots {
                let decision = check_robots(store, &next.normalized, policy, profile, runtime)?;
                if !decision.allowed {
                    return Err(CrawlError::Refused(format!(
                        "redirect target robots policy: {}",
                        decision.reason
                    )));
                }
                decision
            } else {
                RobotsDecision {
                    allowed: true,
                    decision: "not-applicable".to_owned(),
                    reason: "robots retrieval redirect".to_owned(),
                    crawl_delay_ms: 0,
                    source: "not-applicable".to_owned(),
                    source_url: next.normalized.to_string(),
                    status: None,
                    selected_group: "none".to_owned(),
                    cache_age_seconds: None,
                }
            };
            redirects.push(RedirectRecord {
                from_url: current.normalized.to_string(),
                to_url: next.normalized.to_string(),
                status: status.as_u16(),
                selected_headers: select_headers(&response.headers),
                destination,
                robots_decision: redirect_robots.decision,
                robots_reason: redirect_robots.reason,
            });
            if !same_origin(&current.normalized, &next.normalized) {
                headers.remove(IF_NONE_MATCH);
                headers.remove(IF_MODIFIED_SINCE);
            }
            current = next;
            continue;
        }
        let raw_headers = response.headers.clone();
        let selected_headers = select_headers(&raw_headers);
        if let Some(length) = raw_headers
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
            && length > policy.max_compressed_body_bytes.min(max_body_bytes)
        {
            return Err(CrawlError::Refused(format!(
                "Content-Length {length} exceeds compressed byte budget {}",
                policy.max_compressed_body_bytes.min(max_body_bytes)
            )));
        }
        let (body_blob, body, compressed_byte_count) = if status == StatusCode::NOT_MODIFIED {
            (None, Vec::new(), 0)
        } else {
            let encoding = raw_headers
                .get(CONTENT_ENCODING)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("identity")
                .trim()
                .to_ascii_lowercase();
            let compressed_limit = policy.max_compressed_body_bytes.min(max_body_bytes);
            runtime.check_cancelled(CancellationStage::Body)?;
            let (wire_blob, wire_bytes) = store.store_blob_reader(
                response.body,
                compressed_limit,
                if encoding == "identity" {
                    "entity"
                } else {
                    "encoded-entity"
                },
                "standard",
                false,
            )?;
            let wire_count = wire_bytes.len();
            if encoding == "identity" || encoding.is_empty() {
                (Some(wire_blob), wire_bytes, wire_count)
            } else {
                let decoded = decode_content_encoding(&wire_bytes, &encoding, max_body_bytes)?;
                let entity_blob = store.store_blob(&decoded, "entity", "standard", false)?;
                (Some(entity_blob), decoded, wire_count)
            }
        };
        store.record_response_bytes(&reservation, compressed_byte_count)?;
        let final_url = current.normalized.clone();
        return Ok(NetworkResponse {
            destination,
            final_url,
            status,
            headers: selected_headers,
            raw_headers,
            body,
            compressed_byte_count,
            body_blob,
            redirects,
        });
    }
    Err(CrawlError::Network("redirect state exhausted".to_owned()))
}

fn decode_content_encoding(
    bytes: &[u8],
    encoding: &str,
    max_expanded_bytes: usize,
) -> Result<Vec<u8>> {
    match encoding {
        "gzip" | "x-gzip" => read_decoded_bounded(
            flate2::read::GzDecoder::new(Cursor::new(bytes)),
            max_expanded_bytes,
            encoding,
        ),
        "deflate" => {
            let zlib = read_decoded_bounded(
                flate2::read::ZlibDecoder::new(Cursor::new(bytes)),
                max_expanded_bytes,
                encoding,
            );
            zlib.or_else(|_| {
                read_decoded_bounded(
                    flate2::read::DeflateDecoder::new(Cursor::new(bytes)),
                    max_expanded_bytes,
                    encoding,
                )
            })
        }
        "br" => read_decoded_bounded(
            brotli::Decompressor::new(Cursor::new(bytes), 4096),
            max_expanded_bytes,
            encoding,
        ),
        "zstd" => {
            let decoder = zstd::stream::read::Decoder::new(Cursor::new(bytes))
                .map_err(|error| CrawlError::Parser(format!("invalid zstd body: {error}")))?;
            read_decoded_bounded(decoder, max_expanded_bytes, encoding)
        }
        _ => Err(CrawlError::Refused(format!(
            "unsupported Content-Encoding {encoding}"
        ))),
    }
}

fn read_decoded_bounded(
    reader: impl Read,
    max_expanded_bytes: usize,
    encoding: &str,
) -> Result<Vec<u8>> {
    let limit = u64::try_from(max_expanded_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut output = Vec::with_capacity(max_expanded_bytes.min(64 * 1024));
    reader
        .take(limit)
        .read_to_end(&mut output)
        .map_err(|error| CrawlError::Parser(format!("invalid {encoding} body: {error}")))?;
    if output.len() > max_expanded_bytes {
        return Err(CrawlError::Refused(format!(
            "expanded body exceeds byte budget {max_expanded_bytes}"
        )));
    }
    Ok(output)
}

fn request_current_with_retries(
    store: &mut StateStore,
    url: &Url,
    headers: &HeaderMap,
    policy: &FetchPolicy,
    profile: NetworkProfile,
    minimum_delay_ms: u64,
    runtime: &dyn FetchRuntime,
) -> Result<(TransportResponse, ApprovedDestination, ThrottleReservation)> {
    if policy.max_attempts == 0 {
        return Err(CrawlError::InvalidInput(
            "max attempts must be at least one".to_owned(),
        ));
    }
    for attempt in 1..=policy.max_attempts {
        runtime.check_cancelled(CancellationStage::Dns)?;
        let destination = runtime.resolve(url, profile)?;
        let reservation = store.reserve_request(
            &crate::policy::origin(url),
            &destination.selected.to_string(),
            minimum_delay_ms,
            policy.max_origin_requests_per_day,
            policy.max_destination_ip_requests_per_day,
        )?;
        if reservation.wait_ms > 0 {
            std::thread::sleep(Duration::from_millis(reservation.wait_ms));
        }
        let response = runtime.send(&destination, url, headers, policy);
        match response {
            Ok(response) => {
                if !connected_peer_is_approved(response.peer, &destination) {
                    return Err(CrawlError::Refused(format!(
                        "connected peer {} differs from approved address set",
                        response.peer
                    )));
                }
                if retryable_status(response.status) && attempt < policy.max_attempts {
                    let retry_after = retry_after_ms(&response.headers);
                    store.record_response_bytes(&reservation, 0)?;
                    std::thread::sleep(retry_delay(url, attempt, retry_after, policy));
                    continue;
                }
                return Ok((response, destination, reservation));
            }
            Err(CrawlError::Refused(message)) => return Err(CrawlError::Refused(message)),
            Err(error) if attempt < policy.max_attempts => {
                store.record_response_bytes(&reservation, 0)?;
                std::thread::sleep(retry_delay(url, attempt, None, policy));
                drop(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(CrawlError::Network("retry state exhausted".to_owned()))
}

fn retryable_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::REQUEST_TIMEOUT
            | StatusCode::TOO_MANY_REQUESTS
            | StatusCode::INTERNAL_SERVER_ERROR
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
    )
}

fn retry_after_ms(headers: &HeaderMap) -> Option<u64> {
    let value = headers.get("retry-after")?.to_str().ok()?.trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(seconds.saturating_mul(1_000));
    }
    let deadline = DateTime::parse_from_rfc2822(value)
        .ok()?
        .with_timezone(&Utc);
    let millis = deadline
        .signed_duration_since(Utc::now())
        .num_milliseconds();
    Some(u64::try_from(millis.max(0)).unwrap_or(0))
}

fn retry_delay(
    url: &Url,
    attempt: usize,
    retry_after_ms: Option<u64>,
    policy: &FetchPolicy,
) -> Duration {
    let exponent = u32::try_from(attempt.saturating_sub(1))
        .unwrap_or(u32::MAX)
        .min(20);
    let exponential = policy
        .base_backoff_ms
        .saturating_mul(1_u64 << exponent)
        .min(policy.max_backoff_ms);
    let hash = crate::hash::sha256_hex(format!("{}:{attempt}", url.as_str()).as_bytes());
    let jitter_seed = u64::from_str_radix(&hash[..8], 16).unwrap_or(0);
    let jitter = jitter_seed % policy.base_backoff_ms.saturating_div(2).saturating_add(1);
    Duration::from_millis(
        exponential
            .saturating_add(jitter)
            .max(retry_after_ms.unwrap_or(0)),
    )
}

fn parse_crawl_delay_ms(robots: &str, user_agent: &str) -> u64 {
    let mut group_matches = false;
    let mut delay = 0_u64;
    for raw_line in robots.lines() {
        let line = raw_line.split('#').next().unwrap_or_default().trim();
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("user-agent") {
            let candidate = value.trim();
            group_matches = candidate == "*" || candidate.eq_ignore_ascii_case(user_agent);
        } else if group_matches
            && name.trim().eq_ignore_ascii_case("crawl-delay")
            && let Some(milliseconds) = decimal_seconds_to_millis(value.trim())
        {
            delay = milliseconds;
        }
    }
    delay
}

fn decimal_seconds_to_millis(value: &str) -> Option<u64> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    let seconds = whole.parse::<u64>().ok()?;
    if !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let mut milliseconds = fraction.chars().take(3).collect::<String>();
    while milliseconds.len() < 3 {
        milliseconds.push('0');
    }
    let fractional = if milliseconds.is_empty() {
        0
    } else {
        milliseconds.parse::<u64>().ok()?
    };
    seconds.checked_mul(1_000)?.checked_add(fractional)
}

fn pinned_client(destination: &ApprovedDestination, policy: &FetchPolicy) -> Result<Client> {
    let socket = SocketAddr::new(destination.selected, destination.port);
    Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_millis(policy.connect_timeout_ms))
        .timeout(Duration::from_millis(policy.request_timeout_ms))
        .resolve(&destination.host, socket)
        .build()
        .map_err(|error| CrawlError::Network(error.to_string()))
}

fn select_headers(headers: &HeaderMap) -> Value {
    let mut selected = serde_json::Map::new();
    for name in [
        "cache-control",
        "content-language",
        "content-length",
        "content-type",
        "date",
        "etag",
        "expires",
        "last-modified",
        "link",
        "location",
        "retry-after",
        "x-robots-tag",
    ] {
        if let Some(value) = headers.get(name).and_then(|value| value.to_str().ok()) {
            selected.insert(name.to_owned(), Value::String(value.to_owned()));
        }
    }
    if headers.contains_key("set-cookie") {
        selected.insert(
            "set-cookie".to_owned(),
            Value::String("[REDACTED]".to_owned()),
        );
    }
    Value::Object(selected)
}

fn elapsed_millis(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn redact_error(value: &str) -> String {
    let mut redacted = value.to_owned();
    for marker in ["token=", "key=", "sig=", "signature=", "password="] {
        while let Some(start) = redacted.to_ascii_lowercase().find(marker) {
            let value_start = start + marker.len();
            let end = redacted[value_start..]
                .find(['&', ' ', '\'', '"'])
                .map_or(redacted.len(), |offset| value_start + offset);
            redacted.replace_range(value_start..end, "[REDACTED]");
        }
    }
    redacted
}

fn parse_network_profile(policy: &FetchPolicy) -> Result<NetworkProfile> {
    match policy.network_profile.as_str() {
        "automatic-public" => Ok(NetworkProfile::AutomaticPublic),
        "fixture-loopback" => Ok(NetworkProfile::FixtureLoopback),
        value => Err(CrawlError::Refused(format!(
            "unknown network profile {value}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::io::{self, Read, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Mutex;

    use vault_crawl_fixtures::{FixtureServer, fixture_root};

    use super::{
        CancellationStage, FetchContext, FetchPolicy, FetchRuntime, TransportResponse,
        decode_content_encoding, fetch_and_store, fetch_and_store_with_runtime, retry_delay,
    };
    use crate::contract::{Lane, SourceSurface};
    use crate::error::{CrawlError, Result};
    use crate::policy::{ApprovedDestination, NetworkProfile, approve_resolved_destination};
    use crate::store::StateStore;

    fn temporary_root() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("vault-crawl-fetch-{}", uuid::Uuid::new_v4()))
    }

    enum ResolutionStep {
        Addresses(Vec<IpAddr>),
        Error(&'static str),
    }

    enum BodyStep {
        Bytes(Vec<u8>),
        Interrupted,
    }

    enum ReplyStep {
        Response {
            status: u16,
            headers: Vec<(&'static str, &'static str)>,
            peer: IpAddr,
            body: BodyStep,
        },
        Error(&'static str),
    }

    struct InterruptedReader;

    impl Read for InterruptedReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "scripted body interruption",
            ))
        }
    }

    struct ScriptedRuntime {
        resolutions: Mutex<VecDeque<ResolutionStep>>,
        replies: Mutex<VecDeque<ReplyStep>>,
        cancel_at: Option<CancellationStage>,
    }

    impl ScriptedRuntime {
        fn new(resolutions: Vec<ResolutionStep>, replies: Vec<ReplyStep>) -> Self {
            Self {
                resolutions: Mutex::new(resolutions.into()),
                replies: Mutex::new(replies.into()),
                cancel_at: None,
            }
        }

        fn cancelling(stage: CancellationStage) -> Self {
            Self {
                resolutions: Mutex::new(VecDeque::new()),
                replies: Mutex::new(VecDeque::new()),
                cancel_at: Some(stage),
            }
        }
    }

    impl FetchRuntime for ScriptedRuntime {
        fn check_cancelled(&self, stage: CancellationStage) -> Result<()> {
            if self.cancel_at == Some(stage) {
                return Err(CrawlError::Refused(format!("run cancelled at {stage:?}")));
            }
            Ok(())
        }

        fn resolve(&self, url: &url::Url, profile: NetworkProfile) -> Result<ApprovedDestination> {
            let step = self
                .resolutions
                .lock()
                .map_err(|_| CrawlError::Storage("resolution script lock poisoned".to_owned()))?
                .pop_front()
                .ok_or_else(|| CrawlError::Network("resolution script exhausted".to_owned()))?;
            match step {
                ResolutionStep::Addresses(addresses) => {
                    approve_resolved_destination(url, profile, addresses)
                }
                ResolutionStep::Error(message) => Err(CrawlError::Network(message.to_owned())),
            }
        }

        fn send(
            &self,
            destination: &ApprovedDestination,
            _url: &url::Url,
            _headers: &reqwest::header::HeaderMap,
            _policy: &FetchPolicy,
        ) -> Result<TransportResponse> {
            let step = self
                .replies
                .lock()
                .map_err(|_| CrawlError::Storage("reply script lock poisoned".to_owned()))?
                .pop_front()
                .ok_or_else(|| CrawlError::Network("reply script exhausted".to_owned()))?;
            match step {
                ReplyStep::Error(message) => Err(CrawlError::Network(message.to_owned())),
                ReplyStep::Response {
                    status,
                    headers,
                    peer,
                    body,
                } => {
                    let mut header_map = reqwest::header::HeaderMap::new();
                    for (name, value) in headers {
                        header_map.insert(
                            reqwest::header::HeaderName::from_bytes(name.as_bytes())
                                .map_err(|error| CrawlError::Storage(error.to_string()))?,
                            reqwest::header::HeaderValue::from_str(value)
                                .map_err(|error| CrawlError::Storage(error.to_string()))?,
                        );
                    }
                    let body: Box<dyn Read + Send> = match body {
                        BodyStep::Bytes(bytes) => Box::new(std::io::Cursor::new(bytes)),
                        BodyStep::Interrupted => Box::new(InterruptedReader),
                    };
                    Ok(TransportResponse {
                        status: reqwest::StatusCode::from_u16(status)
                            .map_err(|error| CrawlError::Storage(error.to_string()))?,
                        headers: header_map,
                        peer: SocketAddr::new(peer, destination.port),
                        body,
                    })
                }
            }
        }
    }

    fn public_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
    }

    fn response(status: u16, body: impl Into<Vec<u8>>) -> ReplyStep {
        ReplyStep::Response {
            status,
            headers: Vec::new(),
            peer: public_ip(),
            body: BodyStep::Bytes(body.into()),
        }
    }

    fn response_with_headers(
        status: u16,
        headers: Vec<(&'static str, &'static str)>,
        body: impl Into<Vec<u8>>,
    ) -> ReplyStep {
        ReplyStep::Response {
            status,
            headers,
            peer: public_ip(),
            body: BodyStep::Bytes(body.into()),
        }
    }

    fn test_context() -> FetchContext {
        FetchContext {
            caller: "phase1-test".to_owned(),
            lane: Lane::new("default").expect("project ID"),
            source_surface: SourceSurface::Cli,
            host_id: "test-host".to_owned(),
            command: "fetch".to_owned(),
        }
    }

    fn scripted_policy() -> FetchPolicy {
        FetchPolicy {
            minimum_origin_delay_ms: 0,
            max_attempts: 1,
            base_backoff_ms: 0,
            max_backoff_ms: 0,
            ..FetchPolicy::default()
        }
    }

    fn run_scripted(
        runtime: &ScriptedRuntime,
        policy: &FetchPolicy,
        url: &str,
    ) -> std::result::Result<super::FetchOutput, CrawlError> {
        let root = temporary_root();
        let receipts = root.join("receipts");
        let mut store = StateStore::open(&root, &receipts).expect("scripted store");
        let result =
            fetch_and_store_with_runtime(&mut store, url, policy, &test_context(), runtime);
        drop(store);
        fs::remove_dir_all(root).expect("scripted cleanup");
        result
    }

    #[test]
    fn static_fetch_executor_refuses_mixed_rebinding_redirect_and_peer_attacks() {
        let mixed = ScriptedRuntime::new(
            vec![ResolutionStep::Addresses(vec![
                public_ip(),
                IpAddr::V4(Ipv4Addr::LOCALHOST),
            ])],
            vec![],
        );
        assert!(
            run_scripted(&mixed, &scripted_policy(), "https://public.example/")
                .expect_err("mixed DNS must fail")
                .to_string()
                .contains("mixed allowed and forbidden")
        );

        let peer_mismatch = ScriptedRuntime::new(
            vec![
                ResolutionStep::Addresses(vec![public_ip()]),
                ResolutionStep::Addresses(vec![public_ip()]),
            ],
            vec![
                response(404, Vec::new()),
                ReplyStep::Response {
                    status: 200,
                    headers: vec![("content-type", "text/plain")],
                    peer: IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
                    body: BodyStep::Bytes(b"peer mismatch".to_vec()),
                },
            ],
        );
        assert!(
            run_scripted(
                &peer_mismatch,
                &scripted_policy(),
                "https://public.example/"
            )
            .expect_err("peer mismatch must fail")
            .to_string()
            .contains("connected peer")
        );

        let private_redirect = ScriptedRuntime::new(
            vec![
                ResolutionStep::Addresses(vec![public_ip()]),
                ResolutionStep::Addresses(vec![public_ip()]),
                ResolutionStep::Addresses(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]),
            ],
            vec![
                response(404, Vec::new()),
                response_with_headers(302, vec![("location", "http://[::1]/private")], Vec::new()),
            ],
        );
        assert!(
            run_scripted(
                &private_redirect,
                &scripted_policy(),
                "https://public.example/"
            )
            .expect_err("private redirect must fail")
            .to_string()
            .contains("forbidden addresses")
        );

        let redirect_rebinding = ScriptedRuntime::new(
            vec![
                ResolutionStep::Addresses(vec![public_ip()]),
                ResolutionStep::Addresses(vec![public_ip()]),
                ResolutionStep::Addresses(vec![public_ip()]),
                ResolutionStep::Addresses(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]),
            ],
            vec![
                response(404, Vec::new()),
                response_with_headers(
                    302,
                    vec![("location", "https://redirect.example/final")],
                    Vec::new(),
                ),
                response(404, Vec::new()),
            ],
        );
        assert!(
            run_scripted(
                &redirect_rebinding,
                &scripted_policy(),
                "https://public.example/"
            )
            .expect_err("redirect rebinding must fail")
            .to_string()
            .contains("forbidden addresses")
        );
    }

    #[test]
    fn production_retry_delay_honors_retry_after_ceiling() {
        let url = url::Url::parse("https://public.example/").expect("URL");
        assert!(retry_delay(&url, 1, Some(5_000), &scripted_policy()).as_millis() >= 5_000);
    }

    #[test]
    fn robots_status_redirect_parse_timeout_cache_and_throttle_matrix_fails_closed() {
        for status in [401_u16, 403, 400, 429, 500] {
            let runtime = ScriptedRuntime::new(
                vec![ResolutionStep::Addresses(vec![public_ip()])],
                vec![response(status, format!("robots-status-{status}"))],
            );
            let error = run_scripted(
                &runtime,
                &scripted_policy(),
                "https://public.example/private",
            )
            .expect_err("robots status must refuse");
            assert!(
                error.to_string().contains(&format!("status {status}")),
                "{status}: {error}"
            );
        }

        for status in [404_u16, 410] {
            let runtime = ScriptedRuntime::new(
                vec![
                    ResolutionStep::Addresses(vec![public_ip()]),
                    ResolutionStep::Addresses(vec![public_ip()]),
                ],
                vec![
                    response(status, Vec::new()),
                    response_with_headers(
                        200,
                        vec![("content-type", "text/plain")],
                        b"allowed content".to_vec(),
                    ),
                ],
            );
            let output = run_scripted(
                &runtime,
                &scripted_policy(),
                "https://public.example/allowed",
            )
            .expect("absent robots allows content");
            assert_eq!(output.robots_status, Some(status));
            assert_eq!(output.robots_source, "network-absent");
        }

        let redirected = ScriptedRuntime::new(
            vec![
                ResolutionStep::Addresses(vec![public_ip()]),
                ResolutionStep::Addresses(vec![public_ip()]),
                ResolutionStep::Addresses(vec![public_ip()]),
            ],
            vec![
                response_with_headers(302, vec![("location", "/robots-rules")], Vec::new()),
                response(200, b"User-agent: VaultCrawl\nAllow: /\n".to_vec()),
                response_with_headers(
                    200,
                    vec![("content-type", "text/plain")],
                    b"redirected robots allowed".to_vec(),
                ),
            ],
        );
        let redirected_output = run_scripted(
            &redirected,
            &scripted_policy(),
            "https://public.example/allowed",
        )
        .expect("robots redirect");
        assert!(redirected_output.robots_url.ends_with("/robots-rules"));
        assert_eq!(redirected_output.robots_selected_group, "VaultCrawl");

        let deny = ScriptedRuntime::new(
            vec![ResolutionStep::Addresses(vec![public_ip()])],
            vec![response(
                200,
                b"User-agent: VaultCrawl\nDisallow: /private\n".to_vec(),
            )],
        );
        assert!(
            run_scripted(&deny, &scripted_policy(), "https://public.example/private")
                .expect_err("matching deny")
                .to_string()
                .contains("disallows target")
        );

        let malformed = ScriptedRuntime::new(
            vec![ResolutionStep::Addresses(vec![public_ip()])],
            vec![response(200, vec![0xff, 0xfe, 0xfd])],
        );
        assert!(
            run_scripted(&malformed, &scripted_policy(), "https://public.example/")
                .expect_err("malformed robots")
                .to_string()
                .contains("not valid UTF-8")
        );

        let timeout = ScriptedRuntime::new(
            vec![ResolutionStep::Addresses(vec![public_ip()])],
            vec![ReplyStep::Error("scripted robots timeout")],
        );
        assert!(
            run_scripted(&timeout, &scripted_policy(), "https://public.example/")
                .expect_err("robots timeout")
                .to_string()
                .contains("scripted robots timeout")
        );

        let dns_failure = ScriptedRuntime::new(
            vec![ResolutionStep::Error("scripted robots DNS failure")],
            vec![],
        );
        assert!(
            run_scripted(&dns_failure, &scripted_policy(), "https://public.example/")
                .expect_err("robots DNS failure")
                .to_string()
                .contains("scripted robots DNS failure")
        );

        let oversized = ScriptedRuntime::new(
            vec![ResolutionStep::Addresses(vec![public_ip()])],
            vec![response(200, b"User-agent: *\nAllow: /\n".repeat(8))],
        );
        let mut small_robots = scripted_policy();
        small_robots.robots_max_bytes = 8;
        assert!(
            run_scripted(&oversized, &small_robots, "https://public.example/")
                .expect_err("oversized robots")
                .to_string()
                .contains("byte budget")
        );

        let throttled = ScriptedRuntime::new(
            vec![
                ResolutionStep::Addresses(vec![public_ip()]),
                ResolutionStep::Addresses(vec![public_ip()]),
            ],
            vec![
                response(404, Vec::new()),
                response(200, b"content".to_vec()),
            ],
        );
        let mut one_request = scripted_policy();
        one_request.max_origin_requests_per_day = 1;
        assert!(
            run_scripted(&throttled, &one_request, "https://public.example/")
                .expect_err("robots and content share throttle")
                .to_string()
                .contains("daily request cap")
        );

        let root = temporary_root();
        let receipts = root.join("receipts");
        let mut store = StateStore::open(&root, &receipts).expect("cache matrix store");
        let target = url::Url::parse("https://public.example/path").expect("target URL");
        let origin = crate::policy::origin(&target);
        store
            .cache_robots(
                &origin,
                "https://public.example/robots.txt",
                Some(403),
                None,
                0,
                "deny",
                "expired deny",
            )
            .expect("stale deny cache");
        let stale_deny = super::check_robots(
            &mut store,
            &target,
            &scripted_policy(),
            NetworkProfile::AutomaticPublic,
            &ScriptedRuntime::new(vec![], vec![]),
        )
        .expect("stale deny decision");
        assert!(!stale_deny.allowed);
        assert_eq!(stale_deny.source, "stale-cache-deny");

        store
            .cache_robots(
                &origin,
                "https://public.example/robots.txt",
                Some(404),
                None,
                0,
                "absent",
                "expired allow",
            )
            .expect("stale allow cache");
        let stale_allow_error = super::check_robots(
            &mut store,
            &target,
            &scripted_policy(),
            NetworkProfile::AutomaticPublic,
            &ScriptedRuntime::new(
                vec![ResolutionStep::Error("stale allow network failure")],
                vec![],
            ),
        )
        .expect("stale allow failure decision");
        assert!(!stale_allow_error.allowed);
        assert_eq!(stale_allow_error.source, "network-error");
        drop(store);
        fs::remove_dir_all(root).expect("cache matrix cleanup");
    }

    #[test]
    fn cancellation_at_dns_body_stream_and_parse_boundaries_is_receipted() {
        let before_dns = ScriptedRuntime::cancelling(CancellationStage::Dns);
        let dns_error = run_scripted(&before_dns, &scripted_policy(), "https://public.example/")
            .expect_err("DNS cancellation");
        assert!(dns_error.to_string().contains("terminal receipt"));
        assert!(dns_error.to_string().contains("Dns"));

        let before_body = ScriptedRuntime {
            resolutions: Mutex::new(vec![ResolutionStep::Addresses(vec![public_ip()])].into()),
            replies: Mutex::new(vec![response(404, Vec::new())].into()),
            cancel_at: Some(CancellationStage::Body),
        };
        let body_cancel = run_scripted(&before_body, &scripted_policy(), "https://public.example/")
            .expect_err("body cancellation");
        assert!(body_cancel.to_string().contains("terminal receipt"));
        assert!(body_cancel.to_string().contains("Body"));

        let before_parse = ScriptedRuntime {
            resolutions: Mutex::new(
                vec![
                    ResolutionStep::Addresses(vec![public_ip()]),
                    ResolutionStep::Addresses(vec![public_ip()]),
                ]
                .into(),
            ),
            replies: Mutex::new(
                vec![
                    response(404, Vec::new()),
                    response_with_headers(
                        200,
                        vec![("content-type", "text/plain")],
                        b"parse cancellation".to_vec(),
                    ),
                ]
                .into(),
            ),
            cancel_at: Some(CancellationStage::Parse),
        };
        let parse_cancel =
            run_scripted(&before_parse, &scripted_policy(), "https://public.example/")
                .expect_err("parse cancellation");
        assert!(parse_cancel.to_string().contains("terminal receipt"));
        assert!(parse_cancel.to_string().contains("Parse"));

        let interrupted_stream = ScriptedRuntime::new(
            vec![
                ResolutionStep::Addresses(vec![public_ip()]),
                ResolutionStep::Addresses(vec![public_ip()]),
            ],
            vec![
                response(404, Vec::new()),
                ReplyStep::Response {
                    status: 200,
                    headers: vec![("content-type", "text/plain")],
                    peer: public_ip(),
                    body: BodyStep::Interrupted,
                },
            ],
        );
        let stream_error = run_scripted(
            &interrupted_stream,
            &scripted_policy(),
            "https://public.example/",
        )
        .expect_err("stream interruption");
        assert!(stream_error.to_string().contains("terminal receipt"));
        assert!(
            stream_error
                .to_string()
                .contains("scripted body interruption")
        );
    }

    #[test]
    fn compressed_formats_decode_with_an_independent_expanded_limit() {
        let source = b"bounded transport evidence".repeat(32);

        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(&source).expect("gzip input");
        let gzip = gzip.finish().expect("gzip finish");
        assert_eq!(
            decode_content_encoding(&gzip, "gzip", source.len()).expect("gzip decode"),
            source
        );

        let mut deflate =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        deflate.write_all(&source).expect("deflate input");
        let deflate = deflate.finish().expect("deflate finish");
        assert_eq!(
            decode_content_encoding(&deflate, "deflate", source.len()).expect("deflate decode"),
            source
        );

        let mut brotli = Vec::new();
        {
            let mut encoder = brotli::CompressorWriter::new(&mut brotli, 4096, 5, 22);
            encoder.write_all(&source).expect("brotli input");
        }
        assert_eq!(
            decode_content_encoding(&brotli, "br", source.len()).expect("brotli decode"),
            source
        );

        let zstd = zstd::stream::encode_all(source.as_slice(), 3).expect("zstd encode");
        assert_eq!(
            decode_content_encoding(&zstd, "zstd", source.len()).expect("zstd decode"),
            source
        );

        let refused = decode_content_encoding(&gzip, "gzip", source.len() - 1)
            .expect_err("expanded limit must refuse a compressed bomb");
        assert!(refused.to_string().contains("expanded body exceeds"));
        assert!(decode_content_encoding(&gzip, "compress", source.len()).is_err());
    }

    #[test]
    fn invalid_accepted_input_is_terminally_receipted() {
        let root = temporary_root();
        let receipts = root.join("receipts");
        let mut store = StateStore::open(&root, &receipts).expect("store");
        let context = FetchContext {
            caller: "phase1-test".to_owned(),
            lane: Lane::new("default").expect("project ID"),
            source_surface: SourceSurface::Cli,
            host_id: "test-host".to_owned(),
            command: "fetch".to_owned(),
        };
        let error = fetch_and_store(&mut store, "not a url", &FetchPolicy::default(), &context)
            .expect_err("invalid URL must fail");
        assert!(matches!(error, crate::error::CrawlError::Terminal { .. }));
        let count: i64 = store
            .connection_for_tests()
            .query_row(
                "SELECT COUNT(*) FROM receipts WHERE terminal_outcome='failed' AND json_extract(inspected_scope_json,'$.input_url')='[INVALID-URL]'",
                [],
                |row| row.get(0),
            )
            .expect("invalid input receipt");
        assert_eq!(count, 1);
        drop(store);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn promoted_parser_failure_cannot_become_raw_only_success() {
        let server = FixtureServer::start(&fixture_root()).expect("fixture server");
        let root = temporary_root();
        let receipts = root.join("receipts");
        let mut store = StateStore::open(&root, &receipts).expect("store");
        let policy = FetchPolicy {
            network_profile: "fixture-loopback".to_owned(),
            minimum_origin_delay_ms: 0,
            ..FetchPolicy::default()
        };
        let context = FetchContext {
            caller: "phase1-test".to_owned(),
            lane: Lane::new("default").expect("project ID"),
            source_surface: SourceSurface::Cli,
            host_id: "test-host".to_owned(),
            command: "fetch".to_owned(),
        };
        let error = fetch_and_store(
            &mut store,
            &format!("http://{}/malformed.json", server.address()),
            &policy,
            &context,
        )
        .expect_err("malformed promoted JSON must fail");
        assert!(error.to_string().contains("parser failure"));
        let (failed, documents): (i64, i64) = store
            .connection_for_tests()
            .query_row(
                "SELECT (SELECT COUNT(*) FROM receipts WHERE terminal_outcome='failed'),(SELECT COUNT(*) FROM documents)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("parser failure state");
        assert_eq!((failed, documents), (1, 0));
        drop(store);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn fixture_fetch_pins_loopback_extracts_and_queries_without_a_browser() {
        let server = FixtureServer::start(&fixture_root()).expect("fixture server");
        let root = temporary_root();
        let receipts = root.join("receipts");
        let mut store = StateStore::open(&root, &receipts).expect("store");
        let policy = FetchPolicy {
            network_profile: "fixture-loopback".to_owned(),
            ..FetchPolicy::default()
        };
        let context = FetchContext {
            caller: "phase1-test".to_owned(),
            lane: Lane::new("default").expect("project ID"),
            source_surface: SourceSurface::Cli,
            host_id: "test-host".to_owned(),
            command: "fetch".to_owned(),
        };
        let output = fetch_and_store(
            &mut store,
            &format!("http://{}/article", server.address()),
            &policy,
            &context,
        )
        .expect("fetch fixture");
        assert_eq!(output.status, 200);
        assert!(output.document_id.is_some());
        assert!(
            std::path::Path::new(&output.receipt_path)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
        );
        let hits = store.query("fixture", 10).expect("query corpus");
        assert!(!hits.is_empty());
        drop(store);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn public_profile_refuses_loopback_before_connecting() {
        let root = temporary_root();
        let receipts = root.join("receipts");
        let mut store = StateStore::open(&root, &receipts).expect("store");
        let context = FetchContext {
            caller: "phase1-test".to_owned(),
            lane: Lane::new("default").expect("project ID"),
            source_surface: SourceSurface::Cli,
            host_id: "test-host".to_owned(),
            command: "fetch".to_owned(),
        };
        let result = fetch_and_store(
            &mut store,
            "http://[::1]/article",
            &FetchPolicy::default(),
            &context,
        );
        assert!(result.is_err());
        drop(store);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn conditional_revalidation_reuses_the_content_addressed_entity() {
        let server = FixtureServer::start(&fixture_root()).expect("fixture server");
        let root = temporary_root();
        let receipts = root.join("receipts");
        let mut store = StateStore::open(&root, &receipts).expect("store");
        let policy = FetchPolicy {
            network_profile: "fixture-loopback".to_owned(),
            ..FetchPolicy::default()
        };
        let context = FetchContext {
            caller: "phase1-test".to_owned(),
            lane: Lane::new("default").expect("project ID"),
            source_surface: SourceSurface::Cli,
            host_id: "test-host".to_owned(),
            command: "fetch".to_owned(),
        };
        let url = format!("http://{}/article", server.address());
        let first = fetch_and_store(&mut store, &url, &policy, &context).expect("first fetch");
        let second = fetch_and_store(&mut store, &url, &policy, &context).expect("revalidate");
        assert_eq!(first.entity_body_sha256, second.entity_body_sha256);
        assert_eq!(first.document_id, second.document_id);
        assert_eq!(first.job_id, second.job_id);
        assert_ne!(first.run_id, second.run_id);
        assert_eq!(second.cache_outcome, "revalidated-304");
        assert_eq!(store.query("fixture", 10).expect("query").len(), 1);
        let (jobs, attempts): (i64, i64) = store
            .connection_for_tests()
            .query_row(
                "SELECT COUNT(*),MAX(attempt_count) FROM crawl_jobs WHERE job_id=?1",
                [&first.job_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read idempotent job");
        assert_eq!((jobs, attempts), (1, 2));
        drop(store);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn robots_refusal_is_terminal_and_receipted() {
        let server = FixtureServer::start(&fixture_root()).expect("fixture server");
        let root = temporary_root();
        let receipts = root.join("receipts");
        let mut store = StateStore::open(&root, &receipts).expect("store");
        let policy = FetchPolicy {
            network_profile: "fixture-loopback".to_owned(),
            ..FetchPolicy::default()
        };
        let context = FetchContext {
            caller: "phase1-test".to_owned(),
            lane: Lane::new("default").expect("project ID"),
            source_surface: SourceSurface::Cli,
            host_id: "test-host".to_owned(),
            command: "fetch".to_owned(),
        };
        let result = fetch_and_store(
            &mut store,
            &format!("http://{}/private", server.address()),
            &policy,
            &context,
        );
        assert!(matches!(
            result,
            Err(crate::error::CrawlError::Terminal { ref outcome, .. }) if outcome == "refused"
        ));
        let receipt_count: i64 = store
            .connection_for_tests()
            .query_row(
                "SELECT COUNT(*) FROM receipts WHERE terminal_outcome='refused'",
                [],
                |row| row.get(0),
            )
            .expect("count receipts");
        assert_eq!(receipt_count, 1);
        drop(store);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn validated_backup_restores_known_document_blob_and_receipt() {
        let server = FixtureServer::start(&fixture_root()).expect("fixture server");
        let root = temporary_root();
        let receipts = root.join("receipts");
        let mut store = StateStore::open(&root, &receipts).expect("store");
        let policy = FetchPolicy {
            network_profile: "fixture-loopback".to_owned(),
            ..FetchPolicy::default()
        };
        let context = FetchContext {
            caller: "phase1-test".to_owned(),
            lane: Lane::new("default").expect("project ID"),
            source_surface: SourceSurface::Cli,
            host_id: "test-host".to_owned(),
            command: "fetch".to_owned(),
        };
        let output = fetch_and_store(
            &mut store,
            &format!("http://{}/article", server.address()),
            &policy,
            &context,
        )
        .expect("fetch fixture");
        let document_id = output.document_id.as_deref().expect("document ID");
        let now = chrono::Utc::now().to_rfc3339();
        store
            .connection_for_tests()
            .execute(
                "INSERT INTO snapshots(snapshot_id,document_id,captured_at_utc,content_hashes_json,retained_evidence_path,policy_profile) VALUES('snapshot-prior',?1,?2,'{}',NULL,'automatic-public'),('snapshot-current',?1,?2,'{}',NULL,'automatic-public')",
                rusqlite::params![document_id, now],
            )
            .expect("backup snapshots");
        store
            .connection_for_tests()
            .execute(
                "INSERT INTO diffs(diff_id,document_id,prior_snapshot_id,current_snapshot_id,status_changes_json,redirect_changes_json,metadata_changes_json,schema_changes_json,link_changes_json,primary_text_changes_json,materiality_score,downstream_queue_state) VALUES('diff-1',?1,'snapshot-prior','snapshot-current','{}','{}','{}','{}','{}','{}',1.0,'queued')",
                [document_id],
            )
            .expect("backup diff");
        store
            .connection_for_tests()
            .execute(
                "INSERT INTO monitor_events(event_id,monitor_id,snapshot_id,diff_id,lane,host_id,severity,materiality_rule,evidence_hashes_json,state,owner,created_at_utc,updated_at_utc) VALUES('event-1','monitor-1','snapshot-current','diff-1','build','test-host','high','fixture-change','[]','new','phase1-test',?1,?1)",
                [&now],
            )
            .expect("backup monitor event");
        let backup = root.with_extension("backup");
        let report = store.backup_to(&backup).expect("validated backup");
        assert_eq!(report.database_integrity, "ok");
        assert!(report.blob_count >= 3);
        assert_eq!(report.document_count, 1);
        assert_eq!(report.receipt_count, 1);
        assert_eq!(report.compact_receipt_count, 1);
        assert_eq!(report.monitor_event_count, 1);
        drop(store);

        let restored = StateStore::open(&backup, &backup.join("compact-receipts"))
            .expect("open restored backup");
        assert_eq!(
            restored
                .read_blob(&output.entity_body_sha256)
                .expect("restore entity")
                .len(),
            output.byte_count
        );
        assert!(
            !restored
                .query("fixture", 10)
                .expect("restore query")
                .is_empty()
        );
        assert_eq!(
            restored
                .receipt_value(&output.run_id)
                .expect("restore receipt")["terminal_outcome"],
            "success"
        );
        let restored_monitor_events: i64 = restored
            .connection_for_tests()
            .query_row(
                "SELECT COUNT(*) FROM monitor_events WHERE event_id='event-1' AND state='new'",
                [],
                |row| row.get(0),
            )
            .expect("restored monitor state");
        assert_eq!(restored_monitor_events, 1);
        drop(restored);
        fs::remove_dir_all(root).expect("cleanup root");
        fs::remove_dir_all(backup).expect("cleanup backup");
    }

    #[test]
    fn reconcile_marks_corrupt_response_references_unavailable() {
        let server = FixtureServer::start(&fixture_root()).expect("fixture server");
        let root = temporary_root();
        let receipts = root.join("receipts");
        let mut store = StateStore::open(&root, &receipts).expect("store");
        let policy = FetchPolicy {
            network_profile: "fixture-loopback".to_owned(),
            minimum_origin_delay_ms: 0,
            ..FetchPolicy::default()
        };
        let output = fetch_and_store(
            &mut store,
            &format!("http://{}/article", server.address()),
            &policy,
            &test_context(),
        )
        .expect("fetch fixture");
        let relative: String = store
            .connection_for_tests()
            .query_row(
                "SELECT relative_path FROM blob_objects WHERE sha256=?1",
                [&output.entity_body_sha256],
                |row| row.get(0),
            )
            .expect("entity path");
        fs::write(root.join("blobs").join(relative), b"truncated entity").expect("truncate entity");
        let report = store.reconcile().expect("reconcile corruption");
        assert_eq!(report.missing_blobs, 1);
        assert!(report.broken_references >= 1);
        let availability: String = store
            .connection_for_tests()
            .query_row(
                "SELECT availability_state FROM responses WHERE response_id=?1",
                [&output.response_id],
                |row| row.get(0),
            )
            .expect("response availability");
        assert_eq!(availability, "missing");
        drop(store);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn transient_server_errors_retry_to_the_bound_and_stop() {
        let server = FixtureServer::start(&fixture_root()).expect("fixture server");
        let root = temporary_root();
        let receipts = root.join("receipts");
        let mut store = StateStore::open(&root, &receipts).expect("store");
        let policy = FetchPolicy {
            network_profile: "fixture-loopback".to_owned(),
            minimum_origin_delay_ms: 0,
            max_attempts: 3,
            base_backoff_ms: 1,
            max_backoff_ms: 2,
            ..FetchPolicy::default()
        };
        let context = FetchContext {
            caller: "phase1-test".to_owned(),
            lane: Lane::new("default").expect("project ID"),
            source_surface: SourceSurface::Cli,
            host_id: "test-host".to_owned(),
            command: "fetch".to_owned(),
        };
        let result = fetch_and_store(
            &mut store,
            &format!("http://{}/server-error", server.address()),
            &policy,
            &context,
        );
        assert!(matches!(
            result,
            Err(crate::error::CrawlError::Terminal { ref outcome, .. }) if outcome == "failed"
        ));
        let request_count: i64 = store
            .connection_for_tests()
            .query_row(
                "SELECT request_count FROM request_throttles WHERE scope_type='origin'",
                [],
                |row| row.get(0),
            )
            .expect("read throttle counter");
        assert_eq!(request_count, 4, "one robots request plus three attempts");
        drop(store);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn expired_lease_returns_to_queue_with_recovery_evidence() {
        let server = FixtureServer::start(&fixture_root()).expect("fixture server");
        let root = temporary_root();
        let receipts = root.join("receipts");
        let mut store = StateStore::open(&root, &receipts).expect("store");
        let policy = FetchPolicy {
            network_profile: "fixture-loopback".to_owned(),
            minimum_origin_delay_ms: 0,
            ..FetchPolicy::default()
        };
        let context = FetchContext {
            caller: "phase1-test".to_owned(),
            lane: Lane::new("default").expect("project ID"),
            source_surface: SourceSurface::Cli,
            host_id: "test-host".to_owned(),
            command: "fetch".to_owned(),
        };
        let output = fetch_and_store(
            &mut store,
            &format!("http://{}/article", server.address()),
            &policy,
            &context,
        )
        .expect("fetch fixture");
        store
            .connection_for_tests()
            .execute(
                "UPDATE crawl_jobs SET state='running',attempt_id='abandoned-attempt',lease_owner='dead-worker',lease_expires_at_utc='2000-01-01T00:00:00.000Z' WHERE job_id=?1",
                [&output.job_id],
            )
            .expect("simulate stale lease");
        let report = store.reconcile().expect("recover stale lease");
        assert_eq!(report.stale_leases, 1);
        let state: String = store
            .connection_for_tests()
            .query_row(
                "SELECT state FROM crawl_jobs WHERE job_id=?1",
                [&output.job_id],
                |row| row.get(0),
            )
            .expect("read recovered state");
        assert_eq!(state, "pending");
        let recovery_receipts: i64 = store
            .connection_for_tests()
            .query_row(
                "SELECT COUNT(*) FROM receipts WHERE terminal_outcome='recovery' AND json_extract(inspected_scope_json,'$.job_id')=?1",
                [&output.job_id],
                |row| row.get(0),
            )
            .expect("read recovery receipt");
        assert_eq!(recovery_receipts, 1);
        drop(store);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn redirect_hops_are_bounded_and_persisted_parent_to_child() {
        let server = FixtureServer::start(&fixture_root()).expect("fixture server");
        let root = temporary_root();
        let receipts = root.join("receipts");
        let mut store = StateStore::open(&root, &receipts).expect("store");
        let policy = FetchPolicy {
            network_profile: "fixture-loopback".to_owned(),
            minimum_origin_delay_ms: 0,
            ..FetchPolicy::default()
        };
        let context = FetchContext {
            caller: "phase1-test".to_owned(),
            lane: Lane::new("default").expect("project ID"),
            source_surface: SourceSurface::Cli,
            host_id: "test-host".to_owned(),
            command: "fetch".to_owned(),
        };
        let output = fetch_and_store(
            &mut store,
            &format!("http://{}/redirect-article", server.address()),
            &policy,
            &context,
        )
        .expect("follow safe redirect");
        assert_eq!(output.redirect_count, 1);
        assert!(output.final_url.ends_with("/article"));
        let (requests, parented): (i64, i64) = store
            .connection_for_tests()
            .query_row(
                "SELECT COUNT(*),SUM(redirect_parent_request_id IS NOT NULL) FROM requests WHERE job_id=?1",
                [&output.job_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read redirect chain");
        assert_eq!(requests, 2);
        assert_eq!(parented, 1);
        drop(store);
        fs::remove_dir_all(root).expect("cleanup");
    }
}
