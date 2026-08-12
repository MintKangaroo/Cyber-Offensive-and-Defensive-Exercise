CREATE TABLE IF NOT EXISTS tournaments (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    format TEXT NOT NULL,
    status TEXT NOT NULL,
    match_mode TEXT NOT NULL,
    bracket_size INTEGER NOT NULL,
    round_duration_seconds INTEGER NOT NULL,
    active_flag_window INTEGER NOT NULL,
    config TEXT NOT NULL,
    current_stage INTEGER NOT NULL DEFAULT 0,
    winner_entry_id TEXT,
    starts_at REAL,
    completed_at REAL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS tournament_entries (
    id TEXT PRIMARY KEY,
    tournament_id TEXT NOT NULL REFERENCES tournaments(id) ON DELETE CASCADE,
    slug TEXT NOT NULL,
    name TEXT NOT NULL,
    identity_subject TEXT NOT NULL,
    seed INTEGER,
    status TEXT NOT NULL DEFAULT 'registered',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    UNIQUE(tournament_id, slug),
    UNIQUE(tournament_id, identity_subject),
    UNIQUE(tournament_id, seed)
);

CREATE TABLE IF NOT EXISTS tournament_services (
    id TEXT PRIMARY KEY,
    tournament_id TEXT NOT NULL REFERENCES tournaments(id) ON DELETE CASCADE,
    slug TEXT NOT NULL,
    name TEXT NOT NULL,
    base_image TEXT NOT NULL,
    base_image_digest TEXT,
    internal_port INTEGER NOT NULL,
    checker_type TEXT NOT NULL,
    config TEXT NOT NULL,
    created_at REAL NOT NULL,
    UNIQUE(tournament_id, slug)
);

CREATE TABLE IF NOT EXISTS tournament_stages (
    id TEXT PRIMARY KEY,
    tournament_id TEXT NOT NULL REFERENCES tournaments(id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL,
    name TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at REAL NOT NULL,
    completed_at REAL,
    UNIQUE(tournament_id, sequence)
);

CREATE TABLE IF NOT EXISTS tournament_fixtures (
    id TEXT PRIMARY KEY,
    tournament_id TEXT NOT NULL REFERENCES tournaments(id) ON DELETE CASCADE,
    stage_id TEXT NOT NULL REFERENCES tournament_stages(id) ON DELETE CASCADE,
    stage_sequence INTEGER NOT NULL,
    bracket_position INTEGER NOT NULL,
    status TEXT NOT NULL,
    team_a_entry_id TEXT REFERENCES tournament_entries(id) ON DELETE SET NULL,
    team_b_entry_id TEXT REFERENCES tournament_entries(id) ON DELETE SET NULL,
    match_id TEXT REFERENCES matches(id) ON DELETE SET NULL,
    winner_entry_id TEXT REFERENCES tournament_entries(id) ON DELETE SET NULL,
    loser_entry_id TEXT REFERENCES tournament_entries(id) ON DELETE SET NULL,
    result TEXT NOT NULL DEFAULT '{}',
    scheduled_at REAL,
    started_at REAL,
    completed_at REAL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    UNIQUE(tournament_id, stage_sequence, bracket_position),
    UNIQUE(match_id)
);

CREATE TABLE IF NOT EXISTS tournament_match_teams (
    fixture_id TEXT NOT NULL REFERENCES tournament_fixtures(id) ON DELETE CASCADE,
    entry_id TEXT NOT NULL REFERENCES tournament_entries(id) ON DELETE CASCADE,
    match_team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    created_at REAL NOT NULL,
    PRIMARY KEY(fixture_id, entry_id),
    UNIQUE(match_team_id)
);

CREATE INDEX IF NOT EXISTS idx_tournament_fixture_status
    ON tournament_fixtures(tournament_id, status, stage_sequence);

CREATE INDEX IF NOT EXISTS idx_tournament_identity
    ON tournament_entries(tournament_id, identity_subject);

CREATE INDEX IF NOT EXISTS idx_tournament_match_team_entry
    ON tournament_match_teams(entry_id, fixture_id);
