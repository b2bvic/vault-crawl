-- vault-crawl schema version 1
-- Phase 0 contract only. No collector, daemon, renderer, or consumer is activated.

CREATE TABLE crawl_jobs (
    job_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    caller TEXT NOT NULL,
    source_surface TEXT NOT NULL,
    lane TEXT NOT NULL,
    execution_host TEXT NOT NULL,
    purpose TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 0,
    policy_profile TEXT NOT NULL,
    seed_set_json TEXT NOT NULL,
    adapter TEXT NOT NULL,
    created_at_utc TEXT NOT NULL,
    eligible_at_utc TEXT,
    started_at_utc TEXT,
    completed_at_utc TEXT,
    expires_at_utc TEXT,
    page_budget INTEGER NOT NULL CHECK (page_budget >= 0),
    byte_budget INTEGER NOT NULL CHECK (byte_budget >= 0),
    time_budget_ms INTEGER NOT NULL CHECK (time_budget_ms >= 0),
    depth_budget INTEGER NOT NULL CHECK (depth_budget >= 0),
    origin_budget INTEGER NOT NULL CHECK (origin_budget >= 0),
    state TEXT NOT NULL CHECK (state IN ('pending', 'leased', 'running', 'success', 'no-work', 'partial', 'refused', 'failed', 'cancelled')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    attempt_id TEXT,
    lease_owner TEXT,
    heartbeat_at_utc TEXT,
    lease_expires_at_utc TEXT,
    retry_eligible INTEGER NOT NULL DEFAULT 0 CHECK (retry_eligible IN (0, 1)),
    resumable_cursor_json TEXT,
    terminal_result TEXT,
    policy_hash TEXT NOT NULL,
    configuration_hash TEXT NOT NULL,
    seed_manifest_hash TEXT NOT NULL,
    normalization_policy_version TEXT NOT NULL,
    software_hash TEXT NOT NULL
) STRICT;

CREATE TABLE requests (
    request_id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES crawl_jobs(job_id) ON DELETE RESTRICT,
    original_url TEXT NOT NULL,
    normalized_url TEXT NOT NULL,
    method TEXT NOT NULL CHECK (method IN ('GET', 'HEAD', 'POST')),
    request_headers_allowlist_json TEXT NOT NULL,
    attempt INTEGER NOT NULL CHECK (attempt >= 0),
    normalized_host TEXT NOT NULL,
    resolved_addresses_json TEXT NOT NULL,
    selected_pinned_address TEXT,
    connected_peer_address TEXT,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    redirect_parent_request_id TEXT REFERENCES requests(request_id) ON DELETE RESTRICT,
    robots_decision TEXT,
    robots_reason TEXT,
    state TEXT NOT NULL CHECK (state IN ('pending', 'leased', 'running', 'completed', 'refused', 'failed')),
    attempt_id TEXT,
    heartbeat_at_utc TEXT,
    lease_expires_at_utc TEXT,
    retry_eligible INTEGER NOT NULL DEFAULT 0 CHECK (retry_eligible IN (0, 1)),
    terminal_reason TEXT,
    scheduled_at_utc TEXT NOT NULL,
    started_at_utc TEXT,
    finished_at_utc TEXT,
    monotonic_duration_ms INTEGER CHECK (monotonic_duration_ms IS NULL OR monotonic_duration_ms >= 0)
) STRICT;

CREATE INDEX requests_job_state_idx ON requests(job_id, state);
CREATE INDEX requests_normalized_url_idx ON requests(normalized_url);

CREATE TABLE responses (
    response_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE REFERENCES requests(request_id) ON DELETE RESTRICT,
    final_url TEXT NOT NULL,
    status INTEGER,
    selected_headers_json TEXT NOT NULL,
    content_type TEXT,
    encoding TEXT,
    byte_count INTEGER NOT NULL CHECK (byte_count >= 0),
    elapsed_ms INTEGER NOT NULL CHECK (elapsed_ms >= 0),
    entity_body_sha256 TEXT,
    parsed_body_sha256 TEXT,
    etag TEXT,
    last_modified TEXT,
    cache_outcome TEXT NOT NULL,
    parser TEXT,
    parser_version TEXT,
    render_state TEXT NOT NULL CHECK (render_state IN ('not-needed', 'needs-render', 'rendered-manual', 'render-failed')),
    host_id TEXT NOT NULL,
    store_id TEXT,
    retention_class TEXT NOT NULL,
    reference_count INTEGER NOT NULL DEFAULT 0 CHECK (reference_count >= 0),
    hold_state TEXT NOT NULL,
    availability_state TEXT NOT NULL CHECK (availability_state IN ('hash-known', 'available-local', 'exported', 'evicted-under-policy', 'missing')),
    exported_evidence_location TEXT,
    error_class TEXT,
    redacted_diagnostic TEXT
) STRICT;

CREATE TABLE documents (
    document_id TEXT PRIMARY KEY,
    response_id TEXT NOT NULL REFERENCES responses(response_id) ON DELETE RESTRICT,
    source_native_id TEXT,
    normalized_url_identity TEXT NOT NULL,
    observed_canonical_url TEXT,
    title TEXT,
    description TEXT,
    author TEXT,
    published_at_utc TEXT,
    modified_at_utc TEXT,
    primary_markdown_sha256 TEXT,
    primary_text_sha256 TEXT,
    language TEXT,
    word_count INTEGER CHECK (word_count IS NULL OR word_count >= 0),
    headings_json TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    open_graph_json TEXT NOT NULL,
    json_ld_json TEXT NOT NULL,
    schema_types_json TEXT NOT NULL,
    raw_evidence_pointer_json TEXT NOT NULL,
    normalized_artifact_pointer_json TEXT NOT NULL,
    identity_history_json TEXT NOT NULL,
    UNIQUE(normalized_url_identity, response_id)
) STRICT;

CREATE VIRTUAL TABLE corpus_index USING fts5(
    document_id UNINDEXED,
    snapshot_id UNINDEXED,
    caller UNINDEXED,
    lane UNINDEXED,
    adapter UNINDEXED,
    host_id UNINDEXED,
    source_at_utc UNINDEXED,
    captured_at_utc UNINDEXED,
    content_hash UNINDEXED,
    index_schema_version UNINDEXED,
    title,
    body,
    tokenize = 'unicode61 remove_diacritics 2'
);

CREATE TABLE links (
    link_id TEXT PRIMARY KEY,
    source_document_id TEXT NOT NULL REFERENCES documents(document_id) ON DELETE RESTRICT,
    raw_target TEXT NOT NULL,
    resolved_target TEXT,
    normalized_target TEXT,
    relation TEXT,
    anchor_text TEXT,
    location TEXT,
    nofollow INTEGER NOT NULL DEFAULT 0 CHECK (nofollow IN (0, 1)),
    classification TEXT NOT NULL CHECK (classification IN ('internal', 'external', 'unknown'))
) STRICT;

CREATE TABLE snapshots (
    snapshot_id TEXT PRIMARY KEY,
    document_id TEXT NOT NULL REFERENCES documents(document_id) ON DELETE RESTRICT,
    captured_at_utc TEXT NOT NULL,
    content_hashes_json TEXT NOT NULL,
    retained_evidence_path TEXT,
    policy_profile TEXT NOT NULL
) STRICT;

CREATE TABLE diffs (
    diff_id TEXT PRIMARY KEY,
    document_id TEXT NOT NULL REFERENCES documents(document_id) ON DELETE RESTRICT,
    prior_snapshot_id TEXT NOT NULL REFERENCES snapshots(snapshot_id) ON DELETE RESTRICT,
    current_snapshot_id TEXT NOT NULL REFERENCES snapshots(snapshot_id) ON DELETE RESTRICT,
    status_changes_json TEXT NOT NULL,
    redirect_changes_json TEXT NOT NULL,
    metadata_changes_json TEXT NOT NULL,
    schema_changes_json TEXT NOT NULL,
    link_changes_json TEXT NOT NULL,
    primary_text_changes_json TEXT NOT NULL,
    materiality_score REAL NOT NULL,
    downstream_queue_state TEXT NOT NULL
) STRICT;

CREATE TABLE adapter_runs (
    adapter_run_id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES crawl_jobs(job_id) ON DELETE RESTRICT,
    adapter_name TEXT NOT NULL,
    adapter_version TEXT NOT NULL,
    input_scope_json TEXT NOT NULL,
    cursor_json TEXT,
    source_record_count INTEGER NOT NULL CHECK (source_record_count >= 0),
    accepted_count INTEGER NOT NULL CHECK (accepted_count >= 0),
    rejected_count INTEGER NOT NULL CHECK (rejected_count >= 0),
    duplicate_count INTEGER NOT NULL CHECK (duplicate_count >= 0),
    rejection_reasons_json TEXT NOT NULL,
    source_native_identifiers_json TEXT NOT NULL,
    continuation_state_json TEXT NOT NULL
) STRICT;

CREATE TABLE source_registries (
    registry_record_id TEXT PRIMARY KEY,
    registry_type TEXT NOT NULL,
    registry_version TEXT NOT NULL,
    source_path TEXT NOT NULL,
    provenance_json TEXT NOT NULL,
    approving_artifact TEXT,
    lane TEXT NOT NULL,
    execution_host TEXT NOT NULL,
    adapter TEXT NOT NULL,
    source_native_cursor TEXT,
    source_url TEXT,
    active INTEGER NOT NULL DEFAULT 0 CHECK (active IN (0, 1)),
    policy_profile TEXT NOT NULL,
    first_seen_at_utc TEXT,
    last_attempted_at_utc TEXT,
    last_success_at_utc TEXT,
    last_non_empty_at_utc TEXT,
    last_drift_check_at_utc TEXT,
    drift_state TEXT NOT NULL DEFAULT 'unvalidated',
    terminal_state TEXT
) STRICT;

CREATE TABLE provider_usage (
    provider_usage_id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    credential_alias TEXT NOT NULL,
    caller TEXT NOT NULL,
    usage_date_utc TEXT NOT NULL,
    requests INTEGER NOT NULL DEFAULT 0 CHECK (requests >= 0),
    units REAL NOT NULL DEFAULT 0 CHECK (units >= 0),
    estimated_cost REAL NOT NULL DEFAULT 0 CHECK (estimated_cost >= 0),
    actual_cost REAL CHECK (actual_cost IS NULL OR actual_cost >= 0),
    hard_cap REAL NOT NULL DEFAULT 0 CHECK (hard_cap >= 0),
    kill_switch_state TEXT NOT NULL,
    UNIQUE(provider, credential_alias, caller, usage_date_utc)
) STRICT;

CREATE TABLE receipts (
    run_id TEXT PRIMARY KEY,
    parent_run_id TEXT REFERENCES receipts(run_id) ON DELETE RESTRICT,
    receipt_schema_version TEXT NOT NULL,
    producer_version TEXT NOT NULL,
    host_id TEXT NOT NULL,
    source_hashes_json TEXT NOT NULL,
    caller TEXT NOT NULL,
    source_surface TEXT NOT NULL,
    lane TEXT NOT NULL,
    command TEXT NOT NULL,
    execution_host TEXT NOT NULL,
    inspected_scope_json TEXT NOT NULL,
    accepted_ids_json TEXT NOT NULL,
    refused_ids_json TEXT NOT NULL,
    terminal_outcome TEXT NOT NULL CHECK (terminal_outcome IN ('success', 'no-work', 'partial', 'refused', 'failed', 'recovery')),
    counts_json TEXT NOT NULL,
    budget_outcome TEXT NOT NULL,
    monotonic_duration_ms INTEGER NOT NULL CHECK (monotonic_duration_ms >= 0),
    artifact_paths_json TEXT NOT NULL,
    delivery_state TEXT NOT NULL,
    error_summary TEXT,
    software_commit TEXT NOT NULL,
    software_version TEXT NOT NULL,
    schema_versions_json TEXT NOT NULL,
    adapter_version TEXT,
    normalization_policy_version TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    configuration_hash TEXT NOT NULL,
    seed_manifest_hash TEXT NOT NULL,
    evidence_availability_state TEXT NOT NULL,
    compact_receipt_path TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
) STRICT;

CREATE TABLE monitor_events (
    event_id TEXT PRIMARY KEY,
    monitor_id TEXT NOT NULL,
    snapshot_id TEXT NOT NULL REFERENCES snapshots(snapshot_id) ON DELETE RESTRICT,
    diff_id TEXT NOT NULL REFERENCES diffs(diff_id) ON DELETE RESTRICT,
    lane TEXT NOT NULL,
    host_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    materiality_rule TEXT NOT NULL,
    evidence_hashes_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('new', 'acknowledged', 'suppressed', 'held', 'resolved')),
    owner TEXT NOT NULL,
    suppression_rule TEXT,
    hold_reason TEXT,
    resolution_note TEXT,
    created_at_utc TEXT NOT NULL,
    updated_at_utc TEXT NOT NULL
) STRICT;

CREATE INDEX monitor_events_state_idx ON monitor_events(state, severity);
CREATE INDEX source_registries_active_idx ON source_registries(lane, active, adapter);
