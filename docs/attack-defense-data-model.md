# Attack/Defense Data Model

The default additive database is
`${ATTACK_DEFENSE_DATA_DIR}/attack_defense.db`. When
`ATTACK_DEFENSE_DATABASE_URL` is configured, the same logical schema and
migration versions are stored in PostgreSQL. Migrations `0001` through `0003`
create the following tables.

| Table | Purpose and key constraints |
|---|---|
| `matches` | Explicit `exercise`, `attack_defense`, or `hybrid_live_fire` mode; status, clocks, active round and JSON policy configuration |
| `teams` | Match-local symmetric competitors; unique `(match_id, slug)` |
| `rounds` | Stable sequence and correlation ID; unique `(match_id, sequence)` |
| `game_services` | Logical identical service definition and checker type; unique `(match_id, slug)` |
| `team_service_instances` | Runtime-neutral projection; unique `(match_id, team_id, service_id)`; current/previous image digests, runtime ID and game/management endpoints |
| `flags` | Match/round/victim/service scope; token lookup HMAC, no plaintext; unique scope and token hash |
| `flag_submissions` | Accepted/rejected evidence; unique `(attacker_team_id, flag_id)` prevents race awards |
| `service_checks` | Idempotent put/get/benign/protocol/health results; unique `event_id` |
| `patch_submissions` | Image reference/digest, validation result and deployment state |
| `score_ledger` | Append-only score events; unique idempotency `event_id` |
| `score_snapshots` | Last calculated target for a round/team/service/category; used to append only the difference on recalculation |
| `audit_events` | Sanitized append-only evidence with correlation and evidence hashes |
| `audit_event_stream` | Portable monotonic SSE cursor; unique audit event mapping |
| `engine_locks` | SQLite local-worker lease; PostgreSQL uses session advisory locks instead |
| `rate_limits` | Transactional shared action/window counters |
| `runtime_jobs` | Trusted host-runner boundary for sandbox/deploy/restart/rollback |
| `capture_artifacts` | Sanitized-only PCAP metadata, hashes, release gate, counts and server-controlled storage name |
| `capture_releases` | Unique capture/team watermark plus first/last download time and counter |
| `schema_migrations` | Applied migration versions |

## Capture storage

Raw PCAP bytes are never inserted into SQLite or written to the artifact
directory. `capture_artifacts` stores raw and sanitized SHA-256 evidence plus
sanitization counts; the server-controlled file contains only the sanitized
base artifact. Each authenticated team download is re-pseudonymized and
watermarked in memory. The resulting download is not persisted.

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

The migration runner applies ordered SQL files once. PostgreSQL startup uses a
repository-specific migration advisory lock and translates the intentionally
small portable SQL subset to PostgreSQL types/placeholders. It does not touch
auth, event, exercise score, SIEM, EDR, or challenge databases.

Migration `0005_metrics_indexes` adds only covering indexes for cumulative
checker-latency and audit-event Prometheus aggregation. It changes no score or
evidence rows and can be rolled back by dropping those two indexes after the
service has been stopped.

SQLite rollback is an Attack/Defense service stop plus archive/restore of the
independent `ad_data` volume, including the sanitized `captures/` directory.
PostgreSQL rollback requires a database backup/PITR restore plus the matching
sanitized artifact store; there is no automatic live SQLite/PostgreSQL cutover.
See
`services/attack_defense/migrations/README.md`.

Kubernetes support does not add a database migration. It projects validated
runtime results into the existing `team_service_instances` fields and keeps
cluster credentials and plaintext per-service management tokens out of SQLite.

## Optional KOTH tables

KOTH is an opt-in policy for `attack_defense` and `hybrid_live_fire`; it is not
a fourth Match mode and is never attached to `exercise`.

| Table | Purpose |
|---|---|
| `koth_hills` | Match/team/service hill configuration, lease and point policy, plus a reconfiguration epoch |
| `koth_leases` | Append-only acquisition, capture and renewal history tied to the accepted source flag |
| `stealth_incidents` | Internal accepted-attack timeline, disclosure/deadline rounds and frozen score values |
| `stealth_detection_reports` | Append-only defender indicator hashes, safe summaries and internal match result |

`koth_hills` is unique on `(match_id, victim_team_id, service_id)`. A lease is
valid only when it was created after the hill's current `activated_at` epoch,
which prevents an old owner from becoming active again after disable/re-enable.
The source flag relationship is stored for internal evidence only and is never
included in participant or observer projections.

Stealth incident rows reference the accepted `flag_submissions` record but never
copy a flag or token hash. Participant projections omit attacker, submission,
report-match and evidence fields. Reconfiguration advances `activated_at` in
Match config so historical rows remain auditable without re-entering current
scoring or disclosure.

## LiveCTF tournament tables

Migration `0007_tournaments` adds an orchestration layer without changing the
three Match modes or existing score tables.

| Table | Purpose and key constraints |
|---|---|
| `tournaments` | Single-elimination policy, status, bracket size, fixture Match defaults and champion |
| `tournament_entries` | Stable cross-fixture identity; unique tournament slug, identity subject and seed |
| `tournament_services` | Service templates copied into every materialized fixture Match |
| `tournament_stages` | Ordered bracket stages; unique `(tournament_id, sequence)` |
| `tournament_fixtures` | Two entry slots, isolated Match, winner/result and lifecycle; unique stage position and Match |
| `tournament_match_teams` | Operator-only mapping from stable entry to fresh Match-local team ID |

Tournament rows do not own flags, checks, patches or scores. Those remain under
the fixture's ordinary Match foreign-key boundary. Back up migration `0007`
rows, every generated Match and its append-only evidence as one recovery set;
do not drop only the tournament tables after play has begun.
