-- vault-crawl schema version 2
-- Phase 1 static retrieval, cache, blob, robots, artifact, and recovery state.

CREATE TABLE blob_objects (
    sha256 TEXT PRIMARY KEY,
    relative_path TEXT NOT NULL UNIQUE,
    byte_count INTEGER NOT NULL CHECK (byte_count >= 0),
    media_class TEXT NOT NULL CHECK (media_class IN ('entity', 'markdown', 'text', 'document')),
    retention_class TEXT NOT NULL,
    strong_pins INTEGER NOT NULL DEFAULT 0 CHECK (strong_pins >= 0),
    availability_state TEXT NOT NULL CHECK (availability_state IN ('available-local', 'evicted-under-policy', 'missing')),
    created_at_utc TEXT NOT NULL,
    verified_at_utc TEXT
) STRICT;

CREATE TABLE http_cache (
    normalized_url TEXT PRIMARY KEY,
    response_id TEXT NOT NULL REFERENCES responses(response_id) ON DELETE RESTRICT,
    final_url TEXT NOT NULL,
    status INTEGER NOT NULL CHECK (status BETWEEN 100 AND 599),
    selected_headers_json TEXT NOT NULL,
    content_type TEXT,
    etag TEXT,
    last_modified TEXT,
    entity_body_sha256 TEXT REFERENCES blob_objects(sha256) ON DELETE RESTRICT,
    captured_at_utc TEXT NOT NULL,
    revalidated_at_utc TEXT
) STRICT;

CREATE TABLE robots_cache (
    origin TEXT PRIMARY KEY,
    robots_url TEXT NOT NULL,
    status INTEGER,
    body_sha256 TEXT REFERENCES blob_objects(sha256) ON DELETE RESTRICT,
    fetched_at_utc TEXT NOT NULL,
    expires_at_utc TEXT NOT NULL,
    decision_class TEXT NOT NULL CHECK (decision_class IN ('rules', 'absent', 'deny')),
    redacted_reason TEXT NOT NULL
) STRICT;

CREATE TABLE normalized_artifacts (
    document_id TEXT PRIMARY KEY REFERENCES documents(document_id) ON DELETE RESTRICT,
    markdown_sha256 TEXT NOT NULL REFERENCES blob_objects(sha256) ON DELETE RESTRICT,
    text_sha256 TEXT NOT NULL REFERENCES blob_objects(sha256) ON DELETE RESTRICT,
    manifest_json TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
) STRICT;

CREATE TABLE recovery_events (
    recovery_event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    prior_state TEXT,
    current_state TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
) STRICT;

CREATE INDEX blob_objects_availability_idx ON blob_objects(availability_state, strong_pins);
CREATE INDEX http_cache_entity_idx ON http_cache(entity_body_sha256);
CREATE INDEX recovery_events_subject_idx ON recovery_events(subject_id, created_at_utc);
