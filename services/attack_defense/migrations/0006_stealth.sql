CREATE TABLE IF NOT EXISTS stealth_incidents (
    id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    match_id TEXT NOT NULL REFERENCES matches(id) ON DELETE CASCADE,
    round_id TEXT NOT NULL REFERENCES rounds(id) ON DELETE CASCADE,
    occurred_sequence INTEGER NOT NULL,
    attacker_team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    victim_team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    service_id TEXT NOT NULL REFERENCES game_services(id) ON DELETE CASCADE,
    submission_id TEXT NOT NULL UNIQUE REFERENCES flag_submissions(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    detection_deadline_sequence INTEGER NOT NULL,
    disclose_after_sequence INTEGER NOT NULL,
    attacker_points INTEGER NOT NULL,
    defender_points INTEGER NOT NULL,
    detected_at REAL,
    detection_report_id TEXT,
    finalized_at REAL,
    occurred_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS stealth_detection_reports (
    id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    match_id TEXT NOT NULL REFERENCES matches(id) ON DELETE CASCADE,
    round_id TEXT NOT NULL REFERENCES rounds(id) ON DELETE CASCADE,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    service_id TEXT NOT NULL REFERENCES game_services(id) ON DELETE CASCADE,
    indicator_hash TEXT NOT NULL,
    evidence_summary TEXT NOT NULL,
    internal_result TEXT NOT NULL,
    matched_incident_id TEXT REFERENCES stealth_incidents(id) ON DELETE SET NULL,
    submitted_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_stealth_incidents_victim_disclosure
    ON stealth_incidents(match_id, victim_team_id, disclose_after_sequence);

CREATE INDEX IF NOT EXISTS idx_stealth_incidents_scoring
    ON stealth_incidents(match_id, detection_deadline_sequence, status);

CREATE INDEX IF NOT EXISTS idx_stealth_reports_team_time
    ON stealth_detection_reports(match_id, team_id, submitted_at);
