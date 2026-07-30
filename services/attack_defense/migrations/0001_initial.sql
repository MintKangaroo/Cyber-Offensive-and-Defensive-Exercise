PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS matches (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('exercise','attack_defense','hybrid_live_fire')),
    status TEXT NOT NULL DEFAULT 'draft',
    round_duration_seconds INTEGER NOT NULL,
    active_flag_window INTEGER NOT NULL,
    starts_at REAL,
    ends_at REAL,
    current_round_id TEXT,
    config TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS teams (
    id TEXT PRIMARY KEY,
    match_id TEXT NOT NULL REFERENCES matches(id) ON DELETE CASCADE,
    slug TEXT NOT NULL,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL,
    UNIQUE(match_id, slug)
);

CREATE TABLE IF NOT EXISTS rounds (
    id TEXT PRIMARY KEY,
    match_id TEXT NOT NULL REFERENCES matches(id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL,
    status TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    starts_at REAL,
    ends_at REAL,
    finalized_at REAL,
    last_check_at REAL,
    failure_reason TEXT,
    created_at REAL NOT NULL,
    UNIQUE(match_id, sequence)
);

CREATE TABLE IF NOT EXISTS game_services (
    id TEXT PRIMARY KEY,
    match_id TEXT NOT NULL REFERENCES matches(id) ON DELETE CASCADE,
    slug TEXT NOT NULL,
    name TEXT NOT NULL,
    base_image TEXT NOT NULL,
    base_image_digest TEXT,
    internal_port INTEGER NOT NULL,
    checker_type TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    config TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL,
    UNIQUE(match_id, slug)
);

CREATE TABLE IF NOT EXISTS team_service_instances (
    id TEXT PRIMARY KEY,
    match_id TEXT NOT NULL REFERENCES matches(id) ON DELETE CASCADE,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    service_id TEXT NOT NULL REFERENCES game_services(id) ON DELETE CASCADE,
    runtime_id TEXT,
    image_digest TEXT,
    previous_image_digest TEXT,
    status TEXT NOT NULL,
    endpoint TEXT,
    management_endpoint TEXT,
    last_health_at REAL,
    deployed_at REAL,
    updated_at REAL NOT NULL,
    UNIQUE(match_id, team_id, service_id)
);

CREATE TABLE IF NOT EXISTS flags (
    id TEXT PRIMARY KEY,
    match_id TEXT NOT NULL REFERENCES matches(id) ON DELETE CASCADE,
    round_id TEXT NOT NULL REFERENCES rounds(id) ON DELETE CASCADE,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    service_id TEXT NOT NULL REFERENCES game_services(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    encrypted_token BLOB,
    secret_reference TEXT,
    status TEXT NOT NULL,
    valid_from REAL NOT NULL,
    valid_until REAL NOT NULL,
    injected_at REAL,
    retrieved_at REAL,
    created_at REAL NOT NULL,
    UNIQUE(match_id, round_id, team_id, service_id),
    UNIQUE(match_id, token_hash)
);

CREATE TABLE IF NOT EXISTS flag_submissions (
    id TEXT PRIMARY KEY,
    match_id TEXT NOT NULL REFERENCES matches(id) ON DELETE CASCADE,
    round_id TEXT,
    attacker_team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    victim_team_id TEXT,
    service_id TEXT,
    flag_id TEXT,
    submitted_token_hash TEXT NOT NULL,
    result TEXT NOT NULL,
    reject_reason TEXT,
    submitted_at REAL NOT NULL,
    FOREIGN KEY(flag_id) REFERENCES flags(id) ON DELETE SET NULL,
    UNIQUE(attacker_team_id, flag_id)
);

CREATE TABLE IF NOT EXISTS service_checks (
    id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    match_id TEXT NOT NULL REFERENCES matches(id) ON DELETE CASCADE,
    round_id TEXT NOT NULL REFERENCES rounds(id) ON DELETE CASCADE,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    service_id TEXT NOT NULL REFERENCES game_services(id) ON DELETE CASCADE,
    check_type TEXT NOT NULL,
    status TEXT NOT NULL,
    latency_ms REAL,
    error_code TEXT,
    evidence TEXT NOT NULL DEFAULT '{}',
    checked_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS patch_submissions (
    id TEXT PRIMARY KEY,
    match_id TEXT NOT NULL REFERENCES matches(id) ON DELETE CASCADE,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    service_id TEXT NOT NULL REFERENCES game_services(id) ON DELETE CASCADE,
    image_reference TEXT NOT NULL,
    image_digest TEXT,
    previous_image_digest TEXT,
    status TEXT NOT NULL,
    validation_result TEXT NOT NULL DEFAULT '{}',
    submitted_at REAL NOT NULL,
    validated_at REAL,
    deployed_at REAL
);

CREATE TABLE IF NOT EXISTS score_ledger (
    id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    match_id TEXT NOT NULL REFERENCES matches(id) ON DELETE CASCADE,
    round_id TEXT REFERENCES rounds(id) ON DELETE SET NULL,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    service_id TEXT REFERENCES game_services(id) ON DELETE SET NULL,
    score_type TEXT NOT NULL,
    delta INTEGER NOT NULL,
    reason TEXT NOT NULL,
    evidence_hash TEXT NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS score_snapshots (
    natural_key TEXT PRIMARY KEY,
    match_id TEXT NOT NULL,
    round_id TEXT,
    team_id TEXT NOT NULL,
    service_id TEXT,
    score_type TEXT NOT NULL,
    applied_value INTEGER NOT NULL,
    evidence_hash TEXT NOT NULL,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    event_id TEXT PRIMARY KEY,
    correlation_id TEXT,
    actor TEXT NOT NULL,
    team_id TEXT,
    match_id TEXT,
    round_id TEXT,
    service_id TEXT,
    event_type TEXT NOT NULL,
    result TEXT NOT NULL,
    evidence_hash TEXT NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}',
    timestamp REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS engine_locks (
    lock_key TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    lease_until REAL NOT NULL,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS rate_limits (
    subject_key TEXT NOT NULL,
    action TEXT NOT NULL,
    window_start INTEGER NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY(subject_key, action, window_start)
);

CREATE TABLE IF NOT EXISTS runtime_jobs (
    id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    operation TEXT NOT NULL,
    match_id TEXT NOT NULL,
    team_id TEXT,
    service_id TEXT,
    instance_id TEXT,
    payload TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'pending',
    result TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL,
    started_at REAL,
    completed_at REAL
);

CREATE INDEX IF NOT EXISTS idx_rounds_match_status ON rounds(match_id, status);
CREATE INDEX IF NOT EXISTS idx_flags_lookup ON flags(match_id, token_hash);
CREATE INDEX IF NOT EXISTS idx_flags_round ON flags(match_id, round_id, status);
CREATE INDEX IF NOT EXISTS idx_checks_round_team_service ON service_checks(round_id, team_id, service_id);
CREATE INDEX IF NOT EXISTS idx_ledger_match_team ON score_ledger(match_id, team_id);
CREATE INDEX IF NOT EXISTS idx_audit_match_time ON audit_events(match_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_patches_team ON patch_submissions(match_id, team_id, submitted_at);
