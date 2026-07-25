-- vault-crawl schema version 3
-- Persisted request accounting for per-origin and destination-IP throttles.

CREATE TABLE request_throttles (
    scope_type TEXT NOT NULL CHECK (scope_type IN ('origin', 'destination-ip')),
    scope_value TEXT NOT NULL,
    usage_date_utc TEXT NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 0 CHECK (request_count >= 0),
    byte_count INTEGER NOT NULL DEFAULT 0 CHECK (byte_count >= 0),
    last_request_at_utc TEXT NOT NULL,
    PRIMARY KEY(scope_type, scope_value, usage_date_utc)
) STRICT;

CREATE INDEX request_throttles_date_idx
ON request_throttles(usage_date_utc, scope_type, request_count);
