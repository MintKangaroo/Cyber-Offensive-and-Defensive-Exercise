CREATE INDEX IF NOT EXISTS idx_audit_event_type_result
    ON audit_events(event_type, result);

CREATE INDEX IF NOT EXISTS idx_service_checks_latency
    ON service_checks(latency_ms);
