PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS capture_artifacts (
    id TEXT PRIMARY KEY,
    match_id TEXT NOT NULL REFERENCES matches(id) ON DELETE CASCADE,
    round_id TEXT REFERENCES rounds(id) ON DELETE SET NULL,
    service_id TEXT REFERENCES game_services(id) ON DELETE SET NULL,
    status TEXT NOT NULL CHECK (status IN ('ready','quarantined','failed')),
    sanitizer_version TEXT NOT NULL,
    raw_sha256 TEXT NOT NULL,
    sanitized_sha256 TEXT NOT NULL,
    source_size_bytes INTEGER NOT NULL,
    sanitized_size_bytes INTEGER NOT NULL,
    packet_count INTEGER NOT NULL,
    redaction_count INTEGER NOT NULL,
    address_count INTEGER NOT NULL,
    link_type INTEGER NOT NULL,
    captured_from REAL NOT NULL,
    captured_until REAL NOT NULL,
    release_at REAL NOT NULL,
    storage_name TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS capture_releases (
    capture_id TEXT NOT NULL REFERENCES capture_artifacts(id) ON DELETE CASCADE,
    recipient_team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    watermark TEXT NOT NULL,
    first_downloaded_at REAL NOT NULL,
    last_downloaded_at REAL NOT NULL,
    download_count INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY(capture_id, recipient_team_id)
);

CREATE INDEX IF NOT EXISTS idx_capture_match_release
    ON capture_artifacts(match_id, release_at, captured_until);
CREATE INDEX IF NOT EXISTS idx_capture_round
    ON capture_artifacts(round_id, service_id);
