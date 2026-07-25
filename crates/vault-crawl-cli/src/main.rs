use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use serde::Serialize;
use serde_json::{Value, json};
use uuid::Uuid;
use vault_crawl_core::contract::{
    ProjectId, RuntimeCapability, SourceSurface, phase_one_capabilities,
};
use vault_crawl_core::db::verify_temporary_migration;
use vault_crawl_core::extract::extract;
use vault_crawl_core::fetch::{FetchContext, FetchPolicy, fetch_and_store};
use vault_crawl_core::hash::{is_sha256_hex, sha256_hex};
use vault_crawl_core::paths::{ProjectRoots, project_roots};
use vault_crawl_core::schema::{
    repository_root, validate_named_instance, validate_repository_examples,
};
use vault_crawl_core::store::{QueryFilter, StateStore, base_receipt, lane_name, surface_name};
use vault_crawl_core::{IMPLEMENTATION_PHASE, PRODUCER_VERSION};
use vault_crawl_fixtures::{fixture_root, load_manifest};

#[derive(Debug, Parser)]
#[command(
    name = "vault-crawl",
    version,
    about = "Owned static retrieval and local corpus platform"
)]
struct Cli {
    /// User-defined project boundary.
    #[arg(long, default_value = "default", global = true)]
    project: ProjectId,
    /// Project-local state-root override, primarily for isolated tests.
    #[arg(long, global = true)]
    state_root: Option<PathBuf>,
    /// Project-local compact-receipt-root override.
    #[arg(long, global = true)]
    receipt_root: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Report implemented and explicitly unimplemented capabilities.
    Status {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Validate schemas, migrations, storage, fixtures, and fail-closed state.
    Doctor {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Retrieve and preserve transport evidence for one public URL.
    Fetch {
        url: String,
        #[arg(long)]
        json: bool,
    },
    /// Retrieve one public URL and emit extracted Markdown plus provenance.
    Scrape {
        url: String,
        #[arg(long)]
        json: bool,
        /// Emit the Firecrawl direct-scrape response envelope for compatibility testing.
        #[arg(long)]
        firecrawl_compatible: bool,
    },
    /// Parse a local evidence file without making a network request.
    Parse {
        file: PathBuf,
        #[arg(long)]
        source_url: String,
        #[arg(long)]
        content_type: String,
        #[arg(long)]
        json: bool,
    },
    /// Fetch a bounded newline or JSONL URL batch sequentially.
    Batch {
        input: PathBuf,
        #[arg(long, default_value_t = 100)]
        max_items: usize,
        #[arg(long, default_value_t = 100 * 1024 * 1024)]
        max_total_bytes: usize,
        #[arg(long, default_value_t = 20)]
        max_origins: usize,
        #[arg(long, default_value_t = 300_000)]
        max_duration_ms: u64,
        #[arg(long)]
        json: bool,
    },
    /// Retrieve and parse one RSS, Atom, XML, or JSON feed.
    Feed {
        url: String,
        #[arg(long)]
        json: bool,
    },
    /// Query the local FTS5 corpus without making a network request.
    Query {
        query: String,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        rebuild: bool,
        #[arg(long)]
        filter_caller: Option<String>,
        #[arg(long = "filter-project")]
        filter_project: Option<ProjectId>,
        #[arg(long)]
        filter_adapter: Option<String>,
        #[arg(long)]
        filter_host: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Read a terminal receipt by run ID.
    Receipt {
        run_id: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Serialize)]
struct StatusReport {
    schema_version: &'static str,
    producer_version: &'static str,
    implementation_phase: u8,
    phase_name: &'static str,
    promotion_state: &'static str,
    project_roots: Vec<ProjectRoots>,
    capabilities: Vec<RuntimeCapability>,
    http_client: &'static str,
    daemon: &'static str,
    renderer: &'static str,
    timers: &'static str,
    consumers: &'static str,
    external_writes: bool,
}

#[derive(Debug, Serialize)]
struct Check {
    name: &'static str,
    passed: bool,
    detail: String,
}

#[derive(Debug, Serialize)]
struct DoctorReport {
    schema_version: &'static str,
    producer_version: &'static str,
    implementation_phase: u8,
    outcome: &'static str,
    checks: Vec<Check>,
    network_requests: u8,
    external_writes: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ActivationScan {
    directories_scanned: usize,
    files_scanned: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DependencyDenylistScan {
    locked_packages: usize,
    denied_package_names: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LicenseInventoryScan {
    locked_packages: usize,
    inventoried_packages: usize,
}

#[derive(Debug, Clone)]
struct RuntimeConfig {
    project: ProjectId,
    caller: String,
    host_id: String,
    state_root: PathBuf,
    receipt_root: PathBuf,
}

impl RuntimeConfig {
    fn from_cli(cli: &Cli) -> Self {
        let home = env::var_os("HOME").map_or_else(|| PathBuf::from("."), PathBuf::from);
        let state_root = cli.state_root.clone().unwrap_or_else(|| {
            home.join(".local/share/vault-crawl")
                .join(cli.project.as_str())
        });
        let receipt_root = cli.receipt_root.clone().unwrap_or_else(|| {
            home.join(".local/state/vault-crawl/receipts")
                .join(cli.project.as_str())
        });
        Self {
            project: cli.project.clone(),
            caller: "interactive-cli".to_owned(),
            host_id: "local-host".to_owned(),
            state_root,
            receipt_root,
        }
    }

    fn open_store(&self) -> Result<StateStore, String> {
        StateStore::open(&self.state_root, &self.receipt_root).map_err(|error| error.to_string())
    }

    fn fetch_context(&self, command: &str) -> FetchContext {
        FetchContext {
            caller: self.caller.clone(),
            lane: self.project.clone(),
            source_surface: SourceSurface::Cli,
            host_id: self.host_id.clone(),
            command: command.to_owned(),
        }
    }
}

fn run_fetch(
    runtime: &RuntimeConfig,
    url: &str,
    command: &str,
    json_output: bool,
    emit_markdown: bool,
    firecrawl_compatible: bool,
) -> ExitCode {
    let mut store = match runtime.open_store() {
        Ok(store) => store,
        Err(error) => return render_error(&error, json_output),
    };
    let result = fetch_and_store(
        &mut store,
        url,
        &FetchPolicy::default(),
        &runtime.fetch_context(command),
    );
    match result {
        Ok(output) => {
            if firecrawl_compatible {
                let compatible = firecrawl_compatibility_envelope(&output);
                println!(
                    "{}",
                    serde_json::to_string_pretty(&compatible)
                        .expect("serialize compatibility output")
                );
            } else if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&output).expect("serialize fetch output")
                );
            } else if emit_markdown {
                if let Some(document) = &output.document {
                    print!("{}", document.primary_markdown);
                    if !document.primary_markdown.ends_with('\n') {
                        println!();
                    }
                }
                eprintln!("receipt={}", output.receipt_path);
            } else {
                println!(
                    "status={} bytes={} sha256={} cache={} receipt={}",
                    output.status,
                    output.byte_count,
                    output.entity_body_sha256,
                    output.cache_outcome,
                    output.receipt_path
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => render_crawl_error(&error, json_output),
    }
}

fn firecrawl_compatibility_envelope(output: &vault_crawl_core::fetch::FetchOutput) -> Value {
    let document = output.document.as_ref();
    json!({
        "success":true,
        "data":{
            "markdown":document.map_or("", |value| value.primary_markdown.as_str()),
            "links":document.map_or_else(Vec::new, |value| value.links.iter().filter_map(|link| link.resolved_target.clone()).collect::<Vec<_>>()),
            "metadata":{
                "title":document.and_then(|value| value.title.as_deref()),
                "description":document.and_then(|value| value.description.as_deref()),
                "sourceURL":output.final_url,
                "statusCode":output.status,
                "contentType":output.content_type,
            }
        },
        "vault_crawl":{
            "schema_version":"1.0.0",
            "run_id":output.run_id,
            "job_id":output.job_id,
            "response_id":output.response_id,
            "entity_body_sha256":output.entity_body_sha256,
            "receipt_path":output.receipt_path,
            "untrusted_source":true,
        }
    })
}

fn run_parse(
    runtime: &RuntimeConfig,
    file: &Path,
    source_url: &str,
    content_type: &str,
    json_output: bool,
) -> ExitCode {
    let bytes = match fs::read(file) {
        Ok(bytes) => bytes,
        Err(error) => return render_error(&format!("{}: {error}", file.display()), json_output),
    };
    let source_url = match url::Url::parse(source_url) {
        Ok(url) if matches!(url.scheme(), "http" | "https") => url,
        Ok(_) => return render_error("source URL must use http or https", json_output),
        Err(error) => return render_error(&format!("invalid source URL: {error}"), json_output),
    };
    let document = match extract(&bytes, content_type, &source_url) {
        Ok(document) => document,
        Err(error) => return render_error(&error.to_string(), json_output),
    };
    let mut store = match runtime.open_store() {
        Ok(store) => store,
        Err(error) => return render_error(&error, json_output),
    };
    let entity = match store.store_blob(&bytes, "document", "standard", true) {
        Ok(blob) => blob,
        Err(error) => return render_error(&error.to_string(), json_output),
    };
    let markdown = match store.store_blob(
        document.primary_markdown.as_bytes(),
        "markdown",
        "standard",
        true,
    ) {
        Ok(blob) => blob,
        Err(error) => return render_error(&error.to_string(), json_output),
    };
    let text = match store.store_blob(document.primary_text.as_bytes(), "text", "standard", true) {
        Ok(blob) => blob,
        Err(error) => return render_error(&error.to_string(), json_output),
    };
    let run_id = Uuid::new_v4().to_string();
    let artifact_path = match store.write_artifact(
        &run_id,
        &json!({
            "schema_version":"1.0.0",
            "untrusted_source":true,
            "source_url":source_url,
            "entity_body_sha256":entity.sha256,
            "markdown_sha256":markdown.sha256,
            "text_sha256":text.sha256,
            "document":document,
        }),
    ) {
        Ok(path) => path,
        Err(error) => return render_error(&error.to_string(), json_output),
    };
    let mut receipt = base_receipt(
        run_id,
        runtime.host_id.clone(),
        runtime.caller.clone(),
        surface_name(SourceSurface::Cli).to_owned(),
        lane_name(&runtime.project).to_owned(),
        "parse".to_owned(),
    );
    receipt.inspected_scope = json!({"file":file.display().to_string(),"source_url":source_url});
    "success".clone_into(&mut receipt.terminal_outcome);
    receipt.counts = json!({"files":1,"bytes":bytes.len(),"documents":1});
    receipt.source_hashes = vec![entity.sha256.clone(), markdown.sha256, text.sha256];
    receipt.artifact_paths = vec![artifact_path.display().to_string()];
    let receipt_path = match store.write_receipt(&receipt) {
        Ok(path) => path,
        Err(error) => return render_error(&error.to_string(), json_output),
    };
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "document":document,
                "entity_body_sha256":entity.sha256,
                "artifact_manifest_path":artifact_path,
                "receipt_path":receipt_path,
                "network_requests":0
            }))
            .expect("serialize parse output")
        );
    } else {
        print!("{}", document.primary_markdown);
        if !document.primary_markdown.ends_with('\n') {
            println!();
        }
        eprintln!("receipt={}", receipt_path.display());
    }
    ExitCode::SUCCESS
}

#[allow(clippy::too_many_lines)]
fn run_batch(
    runtime: &RuntimeConfig,
    input: &Path,
    max_items: usize,
    max_total_bytes: usize,
    max_origins: usize,
    max_duration_ms: u64,
    json_output: bool,
) -> ExitCode {
    if !(1..=1_000).contains(&max_items)
        || max_total_bytes == 0
        || max_origins == 0
        || max_duration_ms == 0
    {
        return render_error(
            "batch budgets require max-items 1..=1000 and nonzero byte, origin, and time limits",
            json_output,
        );
    }
    let text = match fs::read_to_string(input) {
        Ok(text) => text,
        Err(error) => return render_error(&format!("{}: {error}", input.display()), json_output),
    };
    let mut urls = Vec::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let url = if line.starts_with('{') {
            match serde_json::from_str::<Value>(line)
                .ok()
                .and_then(|value| value.get("url").and_then(Value::as_str).map(str::to_owned))
            {
                Some(url) => url,
                None => {
                    return render_error(
                        "JSONL batch row must contain string field url",
                        json_output,
                    );
                }
            }
        } else {
            line.to_owned()
        };
        urls.push(url);
        if urls.len() > max_items {
            return render_error("batch exceeds max-items", json_output);
        }
    }
    let mut store = match runtime.open_store() {
        Ok(store) => store,
        Err(error) => return render_error(&error, json_output),
    };
    let mut outputs = Vec::new();
    let mut failures = Vec::new();
    let mut origins = BTreeSet::new();
    let mut expanded_bytes = 0usize;
    let started = Instant::now();
    let deadline = Duration::from_millis(max_duration_ms);
    let mut budget_outcome = "within-budget";
    for url in urls {
        if started.elapsed() >= deadline {
            budget_outcome = "time-budget-exhausted";
            break;
        }
        let origin = match url::Url::parse(&url) {
            Ok(parsed) => format!(
                "{}://{}:{}",
                parsed.scheme(),
                parsed.host_str().unwrap_or("[missing-host]"),
                parsed.port_or_known_default().unwrap_or(0)
            ),
            Err(error) => {
                failures
                    .push(json!({"url":safe_url(&url),"error":format!("invalid URL: {error}")}));
                continue;
            }
        };
        origins.insert(origin);
        if origins.len() > max_origins {
            budget_outcome = "origin-budget-exhausted";
            break;
        }
        let remaining_bytes = max_total_bytes.saturating_sub(expanded_bytes);
        if remaining_bytes == 0 {
            budget_outcome = "byte-budget-exhausted";
            break;
        }
        let default_policy = FetchPolicy::default();
        let policy = FetchPolicy {
            max_body_bytes: default_policy.max_body_bytes.min(remaining_bytes),
            max_compressed_body_bytes: default_policy
                .max_compressed_body_bytes
                .min(remaining_bytes),
            request_timeout_ms: default_policy.request_timeout_ms.min(
                u64::try_from(deadline.saturating_sub(started.elapsed()).as_millis())
                    .unwrap_or(u64::MAX),
            ),
            ..default_policy
        };
        match fetch_and_store(&mut store, &url, &policy, &runtime.fetch_context("batch")) {
            Ok(output) => {
                expanded_bytes = expanded_bytes.saturating_add(output.byte_count);
                outputs.push(output);
            }
            Err(error) => failures.push(json!({"url":safe_url(&url),"error":error.to_string()})),
        }
    }
    let terminal_outcome = if budget_outcome != "within-budget" {
        "partial"
    } else if failures.is_empty() {
        "success"
    } else if outputs.is_empty() {
        "failed"
    } else {
        "partial"
    };
    let mut receipt = base_receipt(
        Uuid::new_v4().to_string(),
        runtime.host_id.clone(),
        runtime.caller.clone(),
        surface_name(SourceSurface::Cli).to_owned(),
        lane_name(&runtime.project).to_owned(),
        "batch".to_owned(),
    );
    terminal_outcome.clone_into(&mut receipt.terminal_outcome);
    receipt.inspected_scope = json!({"input":input.display().to_string(),"max_items":max_items,"max_total_bytes":max_total_bytes,"max_origins":max_origins,"max_duration_ms":max_duration_ms});
    receipt.counts = json!({"accepted":outputs.len(),"failed":failures.len(),"origins":origins.len(),"expanded_bytes":expanded_bytes});
    budget_outcome.clone_into(&mut receipt.budget_outcome);
    receipt.source_hashes = outputs
        .iter()
        .map(|output| output.entity_body_sha256.clone())
        .collect();
    let batch_receipt_path = match store.write_receipt(&receipt) {
        Ok(path) => path,
        Err(error) => return render_error(&error.to_string(), json_output),
    };
    let outcome = json!({
        "outcome":terminal_outcome,
        "accepted":outputs,
        "failed":failures,
        "receipt_path":batch_receipt_path,
    });
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&outcome).expect("serialize batch output")
        );
    } else {
        println!(
            "outcome={} accepted={} failed={}",
            outcome["outcome"].as_str().unwrap_or("failed"),
            outcome["accepted"].as_array().map_or(0, Vec::len),
            outcome["failed"].as_array().map_or(0, Vec::len)
        );
    }
    if outcome["outcome"] == "success" {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn run_query(
    runtime: &RuntimeConfig,
    query: &str,
    limit: usize,
    rebuild: bool,
    filter: &QueryFilter,
    json_output: bool,
) -> ExitCode {
    let mut store = match runtime.open_store() {
        Ok(store) => store,
        Err(error) => return render_error(&error, json_output),
    };
    let rebuilt_count = if rebuild {
        match store.rebuild_corpus_index() {
            Ok(count) => Some(count),
            Err(error) => return render_error(&error.to_string(), json_output),
        }
    } else {
        None
    };
    let hits = match store.query_filtered(query, limit, filter) {
        Ok(hits) => hits,
        Err(error) => return render_error(&error.to_string(), json_output),
    };
    let mut receipt = base_receipt(
        Uuid::new_v4().to_string(),
        runtime.host_id.clone(),
        runtime.caller.clone(),
        surface_name(SourceSurface::Cli).to_owned(),
        lane_name(&runtime.project).to_owned(),
        "query".to_owned(),
    );
    receipt.inspected_scope = json!({"query":query,"limit":limit,"filters":filter});
    if hits.is_empty() {
        "no-work"
    } else {
        "success"
    }
    .clone_into(&mut receipt.terminal_outcome);
    receipt.counts =
        json!({"hits":hits.len(),"rebuilt_documents":rebuilt_count,"network_requests":0});
    receipt.source_hashes = hits.iter().map(|hit| hit.content_hash.clone()).collect();
    let receipt_path = match store.write_receipt(&receipt) {
        Ok(path) => path,
        Err(error) => return render_error(&error.to_string(), json_output),
    };
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"hits":hits,"receipt_path":receipt_path,"network_requests":0,"rebuilt_documents":rebuilt_count}))
                .expect("serialize query output")
        );
    } else {
        for hit in hits {
            println!(
                "{}\t{}\t{}",
                hit.document_id, hit.normalized_url, hit.snippet
            );
        }
        eprintln!("receipt={}", receipt_path.display());
    }
    ExitCode::SUCCESS
}

fn run_receipt(runtime: &RuntimeConfig, run_id: &str, json_output: bool) -> ExitCode {
    let store = match runtime.open_store() {
        Ok(store) => store,
        Err(error) => return render_error(&error, json_output),
    };
    match store.receipt_value(run_id) {
        Ok(value) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value).expect("serialize receipt")
                );
            } else {
                println!(
                    "run_id={} outcome={} command={} lane={}",
                    run_id,
                    value["terminal_outcome"].as_str().unwrap_or("unknown"),
                    value["command"].as_str().unwrap_or("unknown"),
                    value["lane"].as_str().unwrap_or("unknown")
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => render_error(&error.to_string(), json_output),
    }
}

fn render_error(error: &str, json_output: bool) -> ExitCode {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"outcome":"failed","error":error}))
                .expect("serialize error")
        );
    } else {
        eprintln!("ERROR: {error}");
    }
    ExitCode::FAILURE
}

fn render_crawl_error(error: &vault_crawl_core::error::CrawlError, json_output: bool) -> ExitCode {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "outcome":error.terminal_outcome().unwrap_or("failed"),
                "error":error.to_string(),
                "receipt_path":error.terminal_receipt_path(),
            }))
            .expect("serialize crawl error")
        );
    } else {
        eprintln!("ERROR: {error}");
    }
    ExitCode::FAILURE
}

fn safe_url(value: &str) -> String {
    url::Url::parse(value).map_or_else(
        |_| "[INVALID-URL]".to_owned(),
        |url| vault_crawl_core::policy::redacted_url(&url),
    )
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let runtime = RuntimeConfig::from_cli(&cli);
    match cli.command {
        Command::Status { json } => {
            render_status(&runtime, json);
            ExitCode::SUCCESS
        }
        Command::Doctor { json } => render_doctor(&runtime, json),
        Command::Fetch { url, json } => run_fetch(&runtime, &url, "fetch", json, false, false),
        Command::Scrape {
            url,
            json,
            firecrawl_compatible,
        } => run_fetch(&runtime, &url, "scrape", json, true, firecrawl_compatible),
        Command::Feed { url, json } => run_fetch(&runtime, &url, "feed", json, true, false),
        Command::Parse {
            file,
            source_url,
            content_type,
            json,
        } => run_parse(&runtime, &file, &source_url, &content_type, json),
        Command::Batch {
            input,
            max_items,
            max_total_bytes,
            max_origins,
            max_duration_ms,
            json,
        } => run_batch(
            &runtime,
            &input,
            max_items,
            max_total_bytes,
            max_origins,
            max_duration_ms,
            json,
        ),
        Command::Query {
            query,
            limit,
            rebuild,
            filter_caller,
            filter_project,
            filter_adapter,
            filter_host,
            json,
        } => run_query(
            &runtime,
            &query,
            limit,
            rebuild,
            &QueryFilter {
                caller: filter_caller,
                lane: filter_project.map(|project| project.to_string()),
                adapter: filter_adapter,
                host_id: filter_host,
            },
            json,
        ),
        Command::Receipt { run_id, json } => run_receipt(&runtime, &run_id, json),
    }
}

fn status_report(projects: &[ProjectId]) -> StatusReport {
    let home = env::var_os("HOME").map_or_else(|| PathBuf::from("."), PathBuf::from);
    StatusReport {
        schema_version: "1.0.0",
        producer_version: PRODUCER_VERSION,
        implementation_phase: IMPLEMENTATION_PHASE,
        phase_name: "static-fetch-extraction-corpus",
        promotion_state: "phase1-promoted",
        project_roots: project_roots(
            &home.join(".local/share/vault-crawl"),
            &home.join(".local/state/vault-crawl/receipts"),
            projects,
        ),
        capabilities: phase_one_capabilities(),
        http_client: "reqwest-rustls-address-pinned",
        daemon: "not-built",
        renderer: "not-built",
        timers: "not-installed",
        consumers: "not-activated",
        external_writes: false,
    }
}

fn render_status(runtime: &RuntimeConfig, json: bool) {
    let report = status_report(std::slice::from_ref(&runtime.project));
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("serialize status report")
        );
    } else {
        println!(
            "vault-crawl phase={} ({})",
            report.implementation_phase, report.phase_name
        );
        println!(
            "network={} daemon={} renderer={} timers={} consumers={}",
            report.http_client, report.daemon, report.renderer, report.timers, report.consumers
        );
    }
}

fn render_doctor(runtime: &RuntimeConfig, json: bool) -> ExitCode {
    let mut checks = doctor_checks();
    checks.push(runtime_state_check(runtime));
    let passed = checks.iter().all(|check| check.passed);
    let report = DoctorReport {
        schema_version: "1.0.0",
        producer_version: PRODUCER_VERSION,
        implementation_phase: IMPLEMENTATION_PHASE,
        outcome: if passed { "success" } else { "failed" },
        checks,
        network_requests: 0,
        external_writes: 0,
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("serialize doctor report")
        );
    } else {
        for check in &report.checks {
            println!(
                "{} {}: {}",
                if check.passed { "PASS" } else { "FAIL" },
                check.name,
                check.detail
            );
        }
        println!("doctor={}", report.outcome);
    }
    if passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn runtime_state_check(runtime: &RuntimeConfig) -> Check {
    let mut store = match runtime.open_store() {
        Ok(store) => store,
        Err(error) => {
            return Check {
                name: "runtime-state-recovery",
                passed: false,
                detail: error,
            };
        }
    };
    match store.reconcile() {
        Ok(report) => match store.integrity() {
            Ok(integrity) => Check {
                name: "runtime-state-recovery",
                passed: integrity == "ok"
                    && report.missing_blobs == 0
                    && report.broken_references == 0,
                detail: format!(
                    "integrity={integrity} orphan_temporary_files_removed={} orphan_blobs_quarantined={} missing_blobs={} broken_references={} stale_leases_recovered={}",
                    report.removed_temporary_files,
                    report.orphan_blobs,
                    report.missing_blobs,
                    report.broken_references,
                    report.stale_leases
                ),
            },
            Err(error) => Check {
                name: "runtime-state-recovery",
                passed: false,
                detail: error.to_string(),
            },
        },
        Err(error) => Check {
            name: "runtime-state-recovery",
            passed: false,
            detail: error.to_string(),
        },
    }
}

#[allow(clippy::too_many_lines)]
fn doctor_checks() -> Vec<Check> {
    let schema_check = match validate_repository_examples() {
        Ok(results) => {
            let failures: Vec<_> = results.iter().filter(|result| !result.valid).collect();
            Check {
                name: "schema-examples",
                passed: failures.is_empty() && results.len() == 5,
                detail: if failures.is_empty() {
                    format!(
                        "{} complete schema trees and common-envelope examples validate",
                        results.len()
                    )
                } else {
                    format!("{} schema examples failed", failures.len())
                },
            }
        }
        Err(error) => Check {
            name: "schema-examples",
            passed: false,
            detail: error,
        },
    };

    let matrix_path = repository_root().join("config/capability-matrix.v1.json");
    let matrix_check = match validate_named_instance("capability", &matrix_path) {
        Ok(validation) => {
            let profile_count = read_json(&matrix_path)
                .ok()
                .and_then(|value| {
                    value
                        .get("profiles")
                        .and_then(Value::as_array)
                        .map(Vec::len)
                })
                .unwrap_or(0);
            Check {
                name: "capability-matrix",
                passed: validation.valid && profile_count > 0,
                detail: if validation.valid {
                    format!(
                        "server-bound default-deny matrix validates; {profile_count} user-defined project profiles are inactive"
                    )
                } else {
                    validation.errors.join("; ")
                },
            }
        }
        Err(error) => Check {
            name: "capability-matrix",
            passed: false,
            detail: error,
        },
    };

    let migration_check = match verify_temporary_migration() {
        Ok(status) => Check {
            name: "fresh-database-migration",
            passed: status.pending == 0
                && status.integrity == "ok"
                && status.checksums_verified == 3,
            detail: format!(
                "latest_applied={} pending={} integrity={} sha256_checksums_verified={}",
                status.latest_applied, status.pending, status.integrity, status.checksums_verified
            ),
        },
        Err(error) => Check {
            name: "fresh-database-migration",
            passed: false,
            detail: error,
        },
    };

    let fixture_check = match load_manifest(&fixture_root()) {
        Ok(manifest) => Check {
            name: "offline-golden-corpus",
            passed: manifest.routes.len() >= 12,
            detail: format!(
                "{} unique loopback fixture routes and body SHA-256 values validate",
                manifest.routes.len()
            ),
        },
        Err(error) => Check {
            name: "offline-golden-corpus",
            passed: false,
            detail: error,
        },
    };

    let threat_path = repository_root().join("fixtures/threat/cases.v1.json");
    let threat_check = match read_json(&threat_path) {
        Ok(value) => {
            let count = value
                .get("cases")
                .and_then(Value::as_array)
                .map_or(0, Vec::len);
            Check {
                name: "threat-fixtures",
                passed: count >= 21,
                detail: format!("{count} pure-policy threat cases present"),
            }
        }
        Err(error) => Check {
            name: "threat-fixtures",
            passed: false,
            detail: error,
        },
    };

    let deferred_threat_path =
        repository_root().join("fixtures/threat/deferred-phase1-cases.v1.json");
    let deferred_threat_check = match read_json(&deferred_threat_path) {
        Ok(value) => {
            let cases = value.get("cases").and_then(Value::as_array);
            let count = cases.map_or(0, Vec::len);
            let status = value.get("implementation_status").and_then(Value::as_str);
            let complete = cases.is_some_and(|cases| {
                cases.iter().all(|case| {
                    ["name", "boundary", "example"].into_iter().all(|field| {
                        case.get(field)
                            .and_then(Value::as_str)
                            .is_some_and(|value| !value.trim().is_empty())
                    })
                })
            });
            Check {
                name: "phase1-transition-threat-inventory",
                passed: status == Some("implemented-phase1") && count >= 13 && complete,
                detail: format!(
                    "{count} URL, platform-proxy, redirect, DNS, and connection transitions are bound to Phase 1 tests"
                ),
            }
        }
        Err(error) => Check {
            name: "phase1-transition-threat-inventory",
            passed: false,
            detail: error,
        },
    };

    let license_path = repository_root().join("licenses/dependency-inventory.json");
    let lock_path = repository_root().join("Cargo.lock");
    let license_check = match validate_license_inventory(&lock_path, &license_path) {
        Ok(scan) => Check {
            name: "dependency-license-inventory",
            passed: true,
            detail: format!(
                "{} Cargo.lock packages exactly match {} inventoried packages with licenses and a matching lock SHA-256; firecrawl_source_copied=false; agpl_code_present=false",
                scan.locked_packages, scan.inventoried_packages
            ),
        },
        Err(error) => Check {
            name: "dependency-license-inventory",
            passed: false,
            detail: error,
        },
    };

    let activation_check = match scan_activation_tree(&repository_root()) {
        Ok(scan) => Check {
            name: "activation-source-tree",
            passed: true,
            detail: format!(
                "recursively inspected {} directories and {} files (excluding .git and target); no service or timer definition filename found",
                scan.directories_scanned, scan.files_scanned
            ),
        },
        Err(error) => Check {
            name: "activation-source-tree",
            passed: false,
            detail: error,
        },
    };

    let transport_dependency_check = match scan_transport_dependency_denylist(&lock_path) {
        Ok(scan) => Check {
            name: "browser-dependency-denylist",
            passed: true,
            detail: format!(
                "{} locked packages checked against {} browser automation package names; none present",
                scan.locked_packages, scan.denied_package_names
            ),
        },
        Err(error) => Check {
            name: "browser-dependency-denylist",
            passed: false,
            detail: error,
        },
    };

    let project_roots_check = project_isolation_check();

    vec![
        schema_check,
        matrix_check,
        migration_check,
        fixture_check,
        threat_check,
        deferred_threat_check,
        license_check,
        project_roots_check,
        activation_check,
        transport_dependency_check,
    ]
}

fn read_json(path: &Path) -> Result<Value, String> {
    serde_json::from_slice(&fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?)
        .map_err(|error| format!("{}: {error}", path.display()))
}

fn load_example_projects() -> Result<Vec<ProjectId>, String> {
    let path = repository_root().join("config/projects.example.json");
    let value = read_json(&path)?;
    if value.get("example_only") != Some(&Value::Bool(true)) {
        return Err(format!("{} must declare example_only=true", path.display()));
    }
    let projects = value
        .get("projects")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{} projects must be an array", path.display()))?;
    let mut parsed = Vec::with_capacity(projects.len());
    for project in projects {
        let id = project
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{} project lacks an id", path.display()))?;
        parsed.push(ProjectId::new(id).map_err(|error| format!("{id}: {error}"))?);
    }
    if parsed.is_empty() {
        return Err(format!(
            "{} must contain at least one project",
            path.display()
        ));
    }
    Ok(parsed)
}

fn project_isolation_check() -> Check {
    let projects = match load_example_projects() {
        Ok(projects) => projects,
        Err(error) => {
            return Check {
                name: "project-root-isolation",
                passed: false,
                detail: error,
            };
        }
    };
    let status = status_report(&projects);
    let root_count = status.project_roots.len();
    let database_count = status
        .project_roots
        .iter()
        .map(|root| &root.database)
        .collect::<BTreeSet<_>>()
        .len();
    let blob_count = status
        .project_roots
        .iter()
        .map(|root| &root.blobs)
        .collect::<BTreeSet<_>>()
        .len();
    let log_count = status
        .project_roots
        .iter()
        .map(|root| &root.logs)
        .collect::<BTreeSet<_>>()
        .len();
    let receipt_count = status
        .project_roots
        .iter()
        .map(|root| &root.compact_receipts)
        .collect::<BTreeSet<_>>()
        .len();
    let passed = [database_count, blob_count, log_count, receipt_count]
        .into_iter()
        .all(|count| count == root_count);
    Check {
        name: "project-root-isolation",
        passed,
        detail: format!(
            "example_projects={root_count} unique_databases={database_count} unique_blobs={blob_count} unique_logs={log_count} unique_receipts={receipt_count}"
        ),
    }
}

fn scan_activation_tree(root: &Path) -> Result<ActivationScan, String> {
    if !root.is_dir() {
        return Err(format!(
            "activation scan root is missing or not a directory: {}",
            root.display()
        ));
    }
    let mut scan = ActivationScan {
        directories_scanned: 0,
        files_scanned: 0,
    };
    scan_activation_directory(root, root, &mut scan)?;
    Ok(scan)
}

fn scan_activation_directory(
    root: &Path,
    directory: &Path,
    scan: &mut ActivationScan,
) -> Result<(), String> {
    scan.directories_scanned += 1;
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("activation scan read {}: {error}", directory.display()))?;
    for entry in entries {
        let entry = entry
            .map_err(|error| format!("activation scan entry {}: {error}", directory.display()))?;
        let path = entry.path();
        let relative = path.strip_prefix(root).map_err(|error| {
            format!(
                "activation scan path {} is outside root: {error}",
                path.display()
            )
        })?;
        if relative.components().count() == 1
            && matches!(entry.file_name().to_str(), Some(".git" | "target"))
        {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("activation scan metadata {}: {error}", path.display()))?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            return Err(format!(
                "activation scan refuses uninspected symlink {}",
                path.display()
            ));
        }
        if file_type.is_dir() {
            scan_activation_directory(root, &path, scan)?;
            continue;
        }
        if !file_type.is_file() {
            return Err(format!(
                "activation scan refuses special file {}",
                path.display()
            ));
        }
        scan.files_scanned += 1;
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .map(str::to_ascii_lowercase);
        if extension
            .as_deref()
            .is_some_and(|value| ["plist", "service", "timer", "socket", "path"].contains(&value))
        {
            return Err(format!(
                "activation definition filename is forbidden in Phase 0: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn scan_transport_dependency_denylist(lock_path: &Path) -> Result<DependencyDenylistScan, String> {
    const DENIED: &[&str] = &[
        "chromiumoxide",
        "fantoccini",
        "headless_chrome",
        "playwright",
        "thirtyfour",
    ];
    let bytes = fs::read(lock_path)
        .map_err(|error| format!("browser denylist read {}: {error}", lock_path.display()))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| format!("browser denylist UTF-8 {}: {error}", lock_path.display()))?;
    let packages = parse_lock_packages(text)?;
    let found = packages
        .iter()
        .map(|(name, _)| name.as_str())
        .filter(|name| DENIED.contains(name))
        .collect::<BTreeSet<_>>();
    if !found.is_empty() {
        return Err(format!(
            "Cargo.lock contains denied browser automation packages: {}",
            found.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    Ok(DependencyDenylistScan {
        locked_packages: packages.len(),
        denied_package_names: DENIED.len(),
    })
}

fn validate_license_inventory(
    lock_path: &Path,
    inventory_path: &Path,
) -> Result<LicenseInventoryScan, String> {
    let lock_bytes = fs::read(lock_path)
        .map_err(|error| format!("license proof read {}: {error}", lock_path.display()))?;
    let lock_text = std::str::from_utf8(&lock_bytes)
        .map_err(|error| format!("license proof UTF-8 {}: {error}", lock_path.display()))?;
    let locked = parse_lock_packages(lock_text)?;
    let inventory = read_json(inventory_path)?;
    if inventory.get("firecrawl_source_copied") != Some(&Value::Bool(false))
        || inventory.get("agpl_code_present") != Some(&Value::Bool(false))
    {
        return Err(
            "license inventory does not declare both Firecrawl source and AGPL code absent"
                .to_owned(),
        );
    }
    let expected_lock_hash = inventory
        .get("cargo_lock_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| "license inventory lacks cargo_lock_sha256".to_owned())?;
    if !is_sha256_hex(expected_lock_hash) || sha256_hex(&lock_bytes) != expected_lock_hash {
        return Err(
            "license inventory Cargo.lock SHA-256 is missing, invalid, or drifted".to_owned(),
        );
    }
    let packages = inventory
        .get("packages")
        .and_then(Value::as_array)
        .ok_or_else(|| "license inventory packages must be an array".to_owned())?;
    let mut inventoried = BTreeSet::new();
    for package in packages {
        let name = package
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| "license package lacks name".to_owned())?;
        let version = package
            .get("version")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("license package {name} lacks version"))?;
        let license = package
            .get("license")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("license package {name} lacks license"))?;
        if license.trim().is_empty()
            || license == "UNKNOWN"
            || license.to_ascii_uppercase().contains("AGPL")
        {
            return Err(format!(
                "license package {name} has refused license {license}"
            ));
        }
        if !inventoried.insert((name.to_owned(), version.to_owned())) {
            return Err(format!("duplicate license package {name} {version}"));
        }
    }
    if inventoried != locked {
        return Err("license inventory name/version set differs from Cargo.lock".to_owned());
    }
    Ok(LicenseInventoryScan {
        locked_packages: locked.len(),
        inventoried_packages: inventoried.len(),
    })
}

fn parse_lock_packages(lock: &str) -> Result<BTreeSet<(String, String)>, String> {
    let mut packages = BTreeSet::new();
    let mut in_package = false;
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    for line in lock.lines().chain(["[[package]]"]) {
        if line == "[[package]]" {
            if in_package {
                let name = name
                    .take()
                    .ok_or_else(|| "Cargo.lock package lacks name".to_owned())?;
                let version = version
                    .take()
                    .ok_or_else(|| format!("Cargo.lock package {name} lacks version"))?;
                if !packages.insert((name.clone(), version.clone())) {
                    return Err(format!("duplicate Cargo.lock package {name} {version}"));
                }
            }
            in_package = true;
        } else if in_package {
            if let Some(value) = line.strip_prefix("name = \"") {
                name = value.strip_suffix('"').map(str::to_owned);
            } else if let Some(value) = line.strip_prefix("version = \"") {
                version = value.strip_suffix('"').map(str::to_owned);
            }
        }
    }
    if packages.is_empty() {
        return Err("Cargo.lock contains no package records".to_owned());
    }
    Ok(packages)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use clap::Parser;
    use vault_crawl_core::contract::{ProjectId, SourceSurface};
    use vault_crawl_core::fetch::{FetchContext, FetchPolicy, fetch_and_store};
    use vault_crawl_core::store::StateStore;
    use vault_crawl_fixtures::{FixtureServer, fixture_root};

    use super::{
        Cli, RuntimeConfig, doctor_checks, firecrawl_compatibility_envelope, repository_root,
        scan_activation_tree, scan_transport_dependency_denylist, status_report,
    };

    #[test]
    fn firecrawl_direct_scrape_fixture_has_exact_required_shape() {
        let server = FixtureServer::start(&fixture_root()).expect("fixture server");
        let root = std::env::temp_dir().join(format!(
            "vault-crawl-compatibility-{}",
            uuid::Uuid::new_v4()
        ));
        let mut store = StateStore::open(&root, &root.join("receipts")).expect("store");
        let policy = FetchPolicy {
            network_profile: "fixture-loopback".to_owned(),
            minimum_origin_delay_ms: 0,
            ..FetchPolicy::default()
        };
        let output = fetch_and_store(
            &mut store,
            &format!("http://{}/article", server.address()),
            &policy,
            &FetchContext {
                caller: "compatibility-test".to_owned(),
                lane: ProjectId::new("default").expect("project ID"),
                source_surface: SourceSurface::Cli,
                host_id: "test-host".to_owned(),
                command: "scrape".to_owned(),
            },
        )
        .expect("fixture scrape");
        let envelope = firecrawl_compatibility_envelope(&output);
        assert_eq!(envelope["success"], true);
        assert!(
            envelope["data"]["markdown"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );
        assert!(
            envelope["data"]["links"]
                .as_array()
                .is_some_and(|value| !value.is_empty())
        );
        assert_eq!(envelope["data"]["metadata"]["statusCode"], 200);
        assert_eq!(envelope["vault_crawl"]["schema_version"], "1.0.0");
        assert_eq!(envelope["vault_crawl"]["untrusted_source"], true);
        assert_eq!(envelope["vault_crawl"]["job_id"], output.job_id);
        drop(store);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn interactive_cli_accepts_arbitrary_valid_projects() {
        let invocation = Cli::try_parse_from([
            "vault-crawl",
            "--project",
            "research-ops",
            "--state-root",
            "/tmp/research-state",
            "--receipt-root",
            "/tmp/research-receipts",
            "status",
        ])
        .expect("parse project invocation");
        let runtime = RuntimeConfig::from_cli(&invocation);
        assert_eq!(runtime.project.as_str(), "research-ops");
        assert_eq!(
            runtime.state_root,
            std::path::Path::new("/tmp/research-state")
        );
        assert_eq!(
            runtime.receipt_root,
            std::path::Path::new("/tmp/research-receipts")
        );
        assert!(Cli::try_parse_from(["vault-crawl", "--project", "../escape", "status"]).is_err());
    }

    #[test]
    fn status_is_explicitly_fail_closed() {
        let projects = [
            ProjectId::new("governance").expect("project ID"),
            ProjectId::new("business-a").expect("project ID"),
            ProjectId::new("business-b").expect("project ID"),
            ProjectId::new("personal").expect("project ID"),
        ];
        let report = status_report(&projects);
        assert_eq!(report.http_client, "reqwest-rustls-address-pinned");
        assert_eq!(report.phase_name, "static-fetch-extraction-corpus");
        assert_eq!(report.promotion_state, "phase1-promoted");
        assert_eq!(report.daemon, "not-built");
        assert_eq!(report.timers, "not-installed");
        assert_eq!(report.consumers, "not-activated");
        assert!(!report.external_writes);
        assert_eq!(report.project_roots.len(), projects.len());
        assert_eq!(
            report
                .project_roots
                .iter()
                .map(|root| &root.database)
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            projects.len()
        );
    }

    #[test]
    fn doctor_contract_checks_pass_without_external_work() {
        let checks = doctor_checks();
        for check in checks {
            assert!(check.passed, "{}: {}", check.name, check.detail);
        }
    }

    #[test]
    fn activation_scan_is_recursive_and_fails_closed() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "vault-crawl-activation-scan-{}-{nonce}",
            std::process::id()
        ));
        let nested = root.join("deep/nested");
        fs::create_dir_all(&nested).expect("create nested activation fixture");
        fs::write(root.join("safe.json"), b"{}").expect("write safe fixture");
        let safe = scan_activation_tree(&root).expect("safe tree should pass");
        assert_eq!(safe.files_scanned, 1);
        fs::write(nested.join("hidden.service"), b"[Unit]").expect("write forbidden fixture");
        let error = scan_activation_tree(&root).expect_err("nested service must fail");
        assert!(error.contains("activation definition filename"));
        fs::remove_dir_all(&root).expect("remove activation fixture");

        let missing = root.join("missing");
        assert!(scan_activation_tree(&missing).is_err());
    }

    #[test]
    fn current_lock_passes_transport_dependency_denylist() {
        let scan = scan_transport_dependency_denylist(&repository_root().join("Cargo.lock"))
            .expect("current Cargo.lock denylist");
        assert!(scan.locked_packages > 0);
        assert!(scan.denied_package_names >= 5);
    }

    #[test]
    fn transport_dependency_denylist_refuses_a_forbidden_package() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "vault-crawl-lock-denylist-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("create lock fixture root");
        let lock = root.join("Cargo.lock");
        fs::write(
            &lock,
            b"version = 4\n\n[[package]]\nname = \"playwright\"\nversion = \"0.0.0\"\n",
        )
        .expect("write lock fixture");
        let error = scan_transport_dependency_denylist(&lock)
            .expect_err("forbidden transport dependency must fail");
        assert!(error.contains("playwright"));
        fs::remove_dir_all(&root).expect("remove lock fixture root");
    }
}
