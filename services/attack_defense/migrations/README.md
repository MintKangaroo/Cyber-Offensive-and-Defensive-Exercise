# Attack/Defense migrations

Migrations are ordered SQL files and are recorded in `schema_migrations`.
Startup applies each file once. They modify only `attack_defense.db`.

The MVP rollback boundary is the whole additive database:

1. stop `attack_defense`;
2. archive the `ad_data` volume;
3. remove or restore only `attack_defense.db`;
4. remove the additive Compose services if required.

No legacy exercise database is changed. Destructive per-table down migrations
are intentionally not automated because restoring the archived append-only
ledger is safer and auditable.
