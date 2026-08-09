# Attack/Defense High-Availability Mode

## Scope

The default local/demo backend remains SQLite and one API/game-engine process.
HA mode is explicitly enabled by setting `ATTACK_DEFENSE_DATABASE_URL` to a
PostgreSQL URL. Every API replica then shares Match, round, flag, score, audit,
runtime-job and rate-limit state.

This change is additive and does not alter the legacy `exercise` stores. Do not
run SQLite and PostgreSQL Attack/Defense processes for the same live Match.

## Coordination guarantees

- Each Match tick holds a PostgreSQL session advisory lock on a deterministic
  signed 64-bit key for the complete initialize/check/finalize operation.
- A process or connection failure releases that session lock at the database.
- Start, pause, resume, end, force-finalize, extend and score recalculation use
  the same exclusive Match boundary.
- Database `clock_timestamp()` is authoritative for rounds, flags, rate-limit
  windows and audit timestamps. `/ready` rejects excessive application/database
  clock skew.
- Rate limits use one PostgreSQL UPSERT counter per subject/action/window. The
  updated count is returned by the same statement, making it atomic across API
  replicas.
- Runtime workers claim jobs with `FOR UPDATE SKIP LOCKED`. Every reclaim gets a
  new fencing token; a stale worker cannot report completion through the API.
- Audit SSE uses an explicit `BIGSERIAL`/`AUTOINCREMENT` sequence instead of the
  SQLite-only `rowid`, preserving `Last-Event-ID` recovery across replicas.
- Uniqueness constraints remain the final idempotency boundary for flags,
  submissions, ledger events, checks, jobs and audit events.

## Local HA profile

Create secrets first. `AD_POSTGRES_PASSWORD` must remain URL-safe; the provided
generator creates a hexadecimal value.

```bash
cp .env.example .env
./scripts/gen_secrets.sh
docker compose stop attack_defense

docker compose --profile ad-ha up -d --build --wait --wait-timeout 180 \
  --scale attack_defense_ha=2 \
  auth ad_registry ad_postgres \
  ad_team_01_notes ad_team_01_vault \
  ad_team_02_notes ad_team_02_vault \
  ad_team_03_notes ad_team_03_vault \
  attack_defense_ha ad_ha_gateway

export ATTACK_DEFENSE_API_URL=http://localhost:8110
python3 -m scripts.bootstrap_attack_defense_demo
python3 -m services.attack_defense.cli ad ha-status
curl -fsS http://localhost:8110/ready
```

`ad_ha_gateway` is a local HAProxy round-robin endpoint with `/ready` health
checks. Port 8110 is bound to loopback and has no TLS. Replace it with the
event's authenticated TLS ingress in production.

The HA profile uses a fresh PostgreSQL database. There is intentionally no
automatic SQLite-to-PostgreSQL live migration. Create HA Matches in PostgreSQL
before the event, or perform an offline, reviewed export/import and ledger
reconciliation.

## Failure behavior

API replica failure:

- HAProxy stops sending new requests after `/ready` fails.
- PostgreSQL transactions roll back incomplete mutations.
- advisory locks held by the failed database session are released.
- another engine replica resumes persisted running Matches on its next poll.

PostgreSQL failure:

- `/ready` returns 503 and HAProxy removes every API replica.
- state-changing requests fail closed; replicas do not fall back to local
  SQLite.
- operators must pause external game traffic/scoring and recover the database.

Runtime worker failure:

- a job is reclaimable after the configured validation/deployment timeout;
- a new claim invalidates the old completion fencing token;
- external deployment operations are not transactionally fenced by
  PostgreSQL, so runtime timeouts must exceed normal cluster rollout time and
  operators must review overlapping operations after severe pauses.

## Production deployment requirements

- Managed or operator-tested PostgreSQL HA with synchronous durability policy,
  backups, point-in-time recovery and monitored replication lag.
- PgBouncer or another reviewed connection pool for larger replica/team counts.
- NTP/chrony on API, database, checker and operator hosts.
- Authenticated TLS between API and PostgreSQL with certificate verification;
  store the DSN in a secret manager, not Compose environment.
- External object storage for sanitized PCAP artifacts. The Compose shared
  volume is single-host only.
- Authenticated TLS load balancer and SSE timeout/reconnect tuning.
- Separate runtime workers and Kubernetes credentials; API replicas still must
  not receive Docker sockets or kubeconfigs.
- Backup restore, forced-primary-failover, replica loss, network partition and
  scoreboard reconciliation exercises before competition.

## Current limitations

- The Compose profile runs one PostgreSQL container and is a functional
  replicated-worker demo, not database high availability.
- Connections are short-lived and unpooled in the MVP.
- PostgreSQL advisory locks coordinate a single database primary; multi-primary
  databases are unsupported.
- The runtime deployment itself cannot be atomically fenced by a database
  token after a worker has already invoked Docker/Kubernetes.
- No online migration or automatic failback to SQLite is provided.

## Verification record

The MVP was verified with two API/game-engine replicas behind the bundled
HAProxy and one PostgreSQL 17 container:

- alternating `/operator/ha/status` responses returned two different engine
  owner IDs while reporting the same running Match;
- stopping one exact API container kept `/ready` at HTTP 200 and preserved the
  current active round through the remaining replica;
- PostgreSQL integration tests passed migration/server-clock readiness,
  advisory-lock exclusion, concurrent submission and shared rate limiting, and
  `SKIP LOCKED` runtime-job fencing (`4 passed`);
- the complete repository regression after the HA change passed (`324 passed,
  4 PostgreSQL tests skipped when no opt-in DSN is configured`).
