PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS audit_event_stream (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE REFERENCES audit_events(event_id) ON DELETE CASCADE
);

INSERT OR IGNORE INTO audit_event_stream(event_id)
SELECT event_id FROM audit_events ORDER BY timestamp,event_id;

CREATE INDEX IF NOT EXISTS idx_audit_stream_event
    ON audit_event_stream(event_id);
