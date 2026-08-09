# Attack/Defense migrations

Migrations are ordered SQL files and are recorded in `schema_migrations`.
Startup applies each file once. They modify only the selected Attack/Defense
SQLite database or PostgreSQL schema.

- `0001_initial.sql`: Match, round, flag, service, patch, ledger and audit core.
- `0002_pcap_privacy.sql`: sanitized capture metadata and recipient release log.
- `0003_audit_stream.sql`: backend-portable monotonic audit/SSE sequence.
- `0004_koth.sql`: optional hill definitions and append-only ownership leases.
- `0005_metrics_indexes.sql`: covering indexes for cumulative checker latency
  and audit event metric aggregation on long-running Matches.
- `0006_stealth.sql`: delayed attack incidents and defender detection reports.

The MVP rollback boundary is the whole additive database:

1. stop `attack_defense`;
2. archive the `ad_data` volume, including `captures/` sanitized artifacts;
3. remove or restore only `attack_defense.db`;
4. remove the additive Compose services if required.

No legacy exercise database is changed. Destructive per-table down migrations
are intentionally not automated because restoring the archived append-only
ledger is safer and auditable.

PostgreSQL applies the same versioned files under a migration advisory lock,
with portable type/placeholder translation. Back up the PostgreSQL database and
sanitized artifact store as one recovery point. Online SQLite-to-PostgreSQL
migration is not implemented.
