CREATE TABLE IF NOT EXISTS koth_hills (
    id TEXT PRIMARY KEY,
    match_id TEXT NOT NULL REFERENCES matches(id) ON DELETE CASCADE,
    victim_team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    service_id TEXT NOT NULL REFERENCES game_services(id) ON DELETE CASCADE,
    enabled INTEGER NOT NULL DEFAULT 1,
    lease_rounds INTEGER NOT NULL,
    points_per_round INTEGER NOT NULL,
    activated_at REAL NOT NULL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    UNIQUE(match_id, victim_team_id, service_id)
);

CREATE TABLE IF NOT EXISTS koth_leases (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    hill_id TEXT NOT NULL REFERENCES koth_hills(id) ON DELETE CASCADE,
    owner_team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    source_flag_id TEXT REFERENCES flags(id) ON DELETE SET NULL,
    acquired_round_id TEXT NOT NULL REFERENCES rounds(id) ON DELETE CASCADE,
    starts_sequence INTEGER NOT NULL,
    expires_after_sequence INTEGER NOT NULL,
    acquired_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_koth_hills_match_enabled
    ON koth_hills(match_id, enabled, service_id);

CREATE INDEX IF NOT EXISTS idx_koth_leases_hill_sequence
    ON koth_leases(hill_id, sequence DESC);

CREATE INDEX IF NOT EXISTS idx_koth_leases_owner_round
    ON koth_leases(owner_team_id, starts_sequence, expires_after_sequence);
