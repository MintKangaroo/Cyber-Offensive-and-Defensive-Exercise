# Attack/Defense Data Model

The additive database is `${ATTACK_DEFENSE_DATA_DIR}/attack_defense.db`.
Migration `0001_initial.sql` creates the following tables.

| Table | Purpose and key constraints |
|---|---|
| `matches` | Explicit `exercise`, `attack_defense`, or `hybrid_live_fire` mode; status, clocks, active round and JSON policy configuration |
| `teams` | Match-local symmetric competitors; unique `(match_id, slug)` |
| `rounds` | Stable sequence and correlation ID; unique `(match_id, sequence)` |
| `game_services` | Logical identical service definition and checker type; unique `(match_id, slug)` |
| `team_service_instances` | Runtime projection; unique `(match_id, team_id, service_id)`; current and previous image digests |
| `flags` | Match/round/victim/service scope; token lookup HMAC, no plaintext; unique scope and token hash |
| `flag_submissions` | Accepted/rejected evidence; unique `(attacker_team_id, flag_id)` prevents race awards |
| `service_checks` | Idempotent put/get/benign/protocol/health results; unique `event_id` |
| `patch_submissions` | Image reference/digest, validation result and deployment state |
| `score_ledger` | Append-only score events; unique idempotency `event_id` |
| `score_snapshots` | Last calculated target for a round/team/service/category; used to append only the difference on recalculation |
| `audit_events` | Sanitized append-only evidence with correlation and evidence hashes |
| `engine_locks` | Persisted local-worker lease |
| `rate_limits` | Transactional action/window counters |
| `runtime_jobs` | Trusted host-runner boundary for sandbox/deploy/restart/rollback |
| `schema_migrations` | Applied migration versions |

## Flag storage

The external token is an opaque 24-byte HMAC output encoded as
`FLAG{base64url}`. Metadata is not encoded in the token. The database stores a
separate keyed lookup hash and `secret_reference=hmac:v1`; the token is
deterministically reconstructed only inside the flag service for injection and
constant-time validation.

## Ledger and weighted totals

Raw categories remain independent. Hybrid supports `attack`, `flag_defense`,
`availability`, `detection`, `containment`, `recovery`, `incident_response`,
`mission_inject`, `penalty`, and `adjustment`. `score_weights` in Match config
affects only the total projection; the raw ledger is never rewritten.

Recalculation compares a deterministic evidence hash and target to
`score_snapshots`. Unchanged inputs append nothing. Changed inputs append only
the signed delta, preserving history. Manual adjustments are independent and
require a reason.

## Migration and rollback

The migration runner applies ordered SQL files once. It does not touch auth,
event, exercise score, SIEM, EDR, or challenge databases. Rollback is an
Attack/Defense service stop plus archive/restore of the independent `ad_data`
volume; see `services/attack_defense/migrations/README.md`.
