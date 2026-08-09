# Attack/Defense MVP Gap Analysis

Date: 2026-07-30  
Repository root: `cyber-range-platform/`

## Phase 0 baseline

The repository was inspected before Attack/Defense code was added. The baseline
command was:

```bash
pytest -q
```

Result: **248 passed, 13 warnings in 21.59s**. The warnings are pre-existing
Starlette and FastAPI lifecycle deprecations.

## Existing architecture

| Area | Existing implementation | Attack/Defense implication |
|---|---|---|
| Backend and entry points | Python 3, FastAPI, one `main.py` per service, Uvicorn entry points in service Dockerfiles | Add a separate FastAPI service so `exercise` routes and processes remain compatible |
| Data persistence | Service-local SQLite using parameterized `sqlite3`; JSON files in `range_control` and the challenge portal; no ORM | Keep SQLite for the one-process demo; add PostgreSQL compatibility, transactions, server time, advisory locks, and versioned migrations for replicated workers |
| Migration tool | No Alembic or repository-wide migration framework | Add an Attack/Defense-only ordered migration runner and SQL migrations; do not retrofit existing databases |
| Authentication | `auth` issues HS256 JWTs with `role`, `team_id`, and `match_id`; `shared.rbac` validates JWT/static tokens | Extend the shared identity object to retain match/team claims and add `competitor`/`operator` aliases while preserving red/blue/instructor |
| RBAC | `instructor`, `red`, `blue`, `observer`; development falls open only if no auth configuration exists | Operator endpoints reuse instructor/operator; participant endpoints require competitor/red/blue plus token membership claims |
| Match and Team | `range_control` stores matches and team indexes in JSON; no relational Team entity | Keep this registry for exercise mode. The new service owns relational Attack/Defense and Hybrid matches, teams, and memberships in its database |
| Challenges and flags | 69 challenge definitions; challenge-specific deterministic HMAC flags; match rotation by namespacing `match::team` | Reuse the deterministic HMAC pattern and constant-time comparison, but implement opaque match × round × victim × service flags and hashed lookup |
| Scores | `scoring_engine` has idempotent achievements and materialized team scores keyed by scenario | Preserve it for exercise mode. Attack/Defense needs an append-only `score_ledger` because defense, availability, replay, and recalculation have different semantics |
| Events | `event_collector` persists deduplicated events, broadcasts WebSocket and SSE, and forwards to scoring | Reuse its event contract for sanitized public events; keep detailed evidence in the new append-only audit table |
| Control Tower | `instructor_api`, `range_control`, and the React Control Tower provide scenario, safety, score adjustment, and audit operations | Expose the requested operator routes from the new service; Control Tower integration can consume those routes without changing legacy APIs |
| SIEM/EDR/AAR | Separate FastAPI services fed through the existing event collector | No rewrite. Sanitized Attack/Defense events can flow through the existing collector; detailed records remain local |
| Prometheus | `observability` scrapes service `/health` payloads and renders Prometheus text | Add native bounded-cardinality Attack/Defense metrics and add the service to observability targets |
| QA and tests | Pytest unit tests, challenge QA scripts, smoke/isolation scripts, k6 load tests | Add unit, API integration, security, service functional/exploitability, and opt-in load profiles |
| Deployment | Root Docker Compose; per-twin internal bridge networks; match deployment/teardown shell scripts; no Docker socket in services | Add a safe runtime abstraction. Compose is driven from a trusted host-side CLI, never from the API container via a mounted socket |
| Scheduler | No Celery/RQ/Redis/APScheduler worker | Add an optional in-process tick loop with the same idempotent engine callable from a separate worker later |

## Reusable components

- FastAPI/Pydantic service layout and Docker build convention.
- JWT creation in `services/auth` and shared RBAC validation.
- Parameterized SQLite access and event-id idempotency patterns.
- Deterministic HMAC generation used by challenge graders.
- Existing anti-cheat hashing/rate-limit concepts.
- Event Collector SSE/WebSocket bus for sanitized match/score updates.
- Existing isolated Docker networks, no Docker socket mounts, and match
  deployment scripts.
- Existing observability renderer and health scraping.
- SIEM, EDR, ICS/OT twins, scenario engine, inject engine, AAR, challenge QA,
  and exercise scoring remain unchanged in `exercise` mode and are composed
  through policy interfaces only in `hybrid_live_fire`.

## Components that require extension

- `shared.rbac.Identity`: retain JWT `team_id`/`match_id`; accept symmetric
  competitor and operator roles without invalidating legacy roles.
- Root Compose and observability target list: add the Attack/Defense API/engine
  and its persistent volume/network attachments.
- README and operational documentation: describe the separate mode, demo,
  security boundary, and limitations.
- Authentication bootstrap: demo competitors need JWTs carrying the new match
  and team membership.

## New components

- Relational Match, Round, Team, GameService, TeamServiceInstance, Flag,
  FlagSubmission, ServiceCheck, PatchSubmission, ScoreLedger, AuditEvent, and
  rate-limit records.
- Explicit round state machine and idempotent tick/recovery engine.
- Match-scoped HMAC flag lifecycle, protected token storage, injection adapters,
  and a non-oracular submission API.
- Checker protocol and aggregation policy.
- Mode strategies for `exercise`, `attack_defense`, and `hybrid_live_fire`,
  configurable independent score categories/weights, and delayed scoreboard
  projections. Hybrid retains Attack, Flag Defense, Availability, Detection,
  Containment, Recovery, Incident Response, Mission Inject, and Penalty as
  distinct ledger and UI fields.
- `ServiceRuntime` protocol with a safe local/in-memory implementation for
  tests, a host-side Docker Compose implementation, and an optional trusted
  host-side Kubernetes adapter with validated manifest generation.
- Patch policy, validation state machine, deployment and rollback orchestration.
- Two intentionally vulnerable, patchable service images: Vulnerable Notes and
  File Vault, each with management-only injection/checking APIs.
- Operator/participant APIs, CLI, demo bootstrap, metrics, and load profile.

## Conflicts and compatibility risks

1. Legacy `Match` data is JSON and represents red/blue role-separated
   exercises. Reusing it in place would overload its meaning and make rollback
   unsafe. The new relational Match therefore has an explicit `mode` and lives
   in an isolated database.
2. Existing challenge flags are challenge/team-scoped and often expose
   recognizable metadata. They cannot satisfy round/service expiry semantics.
   The new flag codec is separate but follows the same HMAC design principle.
3. Existing scoring awards one achievement forever, whereas Attack/Defense
   defense and availability recur per round. Sharing that table would cause
   collisions, so the new ledger is authoritative only for
   `mode=attack_defense` or `mode=hybrid_live_fire`.
4. Existing teams are red or blue. In symmetric mode, legacy red/blue users are
   accepted as competitors for compatibility, while new users use
   `role=competitor`.
5. The existing event schema has no Attack/Defense-specific event enumeration.
   Public integration uses sanitized generic events plus metadata; the complete
   typed evidence remains in the new audit table to avoid breaking consumers.

## Security findings

- `shared.rbac` intentionally fails open when no auth settings exist. This is
  acceptable only for the documented development profile. The Attack/Defense
  service refuses participant mutations in that state unless
  `ATTACK_DEFENSE_ALLOW_INSECURE_DEV_AUTH=true`.
- Existing challenge submission routes trust a body `team_id` and do not
  authenticate. The new flag and patch routes never take participant identity
  from the request body.
- Some legacy administrative reads lack RBAC. New checker, flag, patch, evidence,
  and operator-detail routes are always operator-gated.
- Existing JSON state files are neither transactional nor process-safe. New game
  state uses database transactions and uniqueness constraints. SQLite uses
  `BEGIN IMMEDIATE`, WAL and a persisted lease for the one-process demo.
- Replicated workers use shared PostgreSQL, session advisory Match locks, DB
  server time, atomic UPSERT rate-limit counters and `SKIP LOCKED` job claims.
  The bundled single PostgreSQL container demonstrates coordination but is not
  database HA; production still requires a tested PostgreSQL HA service.
- Docker Compose cannot express tournament-grade per-pod egress,
  bandwidth/connection quotas, or identity-aware network policy. The optional
  Kubernetes runtime now creates team/sandbox namespaces and deny-by-default
  policy, but production must supply and verify a NetworkPolicy-capable CNI,
  gateway connection/bandwidth controls and the API control plane.
- An API container controlling Docker via `/var/run/docker.sock` would be root
  equivalent. It is explicitly prohibited. Runtime changes are emitted as
  signed/validated host-side jobs for the CLI runner.
- Docker image config alone cannot prove absence of malicious code or checker
  fingerprinting. Patch validation checks manifest policy, registry namespace,
  digest pinning, size, lineage declaration, hidden functional checks, and
  resource/time limits; stronger sandboxing and image scanning remain required.
- Secrets must be supplied through Docker secrets or an external secret manager
  in production. Development environment variables are not a production secret
  boundary.

## Implementation plan and decision record

### Phase 1 — core

Create `services/attack_defense` with versioned migrations, repositories,
domain schemas, flag service, score ledger, state machine, engine, and API.
Every externally retried mutation has a unique deterministic event/idempotency
key. State transitions use compare-and-set updates inside an immediate
transaction.

### Phase 2 — symmetric services

Add two small FastAPI service images under
`services/attack_defense/demo_services/{vulnerable_notes,file_vault}`. Each has a normal user
workflow and a management-token protected flag injection endpoint. Compose demo
instances use identical base builds and per-team data volumes.

### Phase 3 — scoring

Finalize rounds from persisted submissions and checks. Ledger event IDs are
derived from match/round/team/service/type, making recalculation deterministic.
Recalculation first reverses/replaces only derived entries for the selected
scope; manual adjustments remain append-only and untouched.

### Phase 4 — patches

Accept digest-pinned images from an allowed team namespace, persist policy
results, and drive a validation/deployment state machine. Runtime calls are
dependency-injected. Deployment stores the previous digest, performs replace,
runs post-deploy checks, and rolls back on failure.

### Phase 5 — operations

Add operator/participant routes, metrics, audit/evidence queries, CLI, demo
bootstrap, root Compose profile, Make target, Kubernetes policy examples,
documentation, and test/load profiles.

## Migration and rollback strategy

- Attack/Defense tables live in `${ATTACK_DEFENSE_DATA_DIR}/attack_defense.db`
  by default or in the explicitly configured PostgreSQL database. No existing
  exercise database/table is modified.
- Ordered migrations are recorded in `schema_migrations`; startup applies each
  migration once in one transaction.
- Forward migrations are additive for the MVP. The rollback procedure is:
  stop the Attack/Defense service, archive its data volume, remove only the
  `ad_data` volume (or restore the archived DB), and start the legacy stack.
- Root Compose additions are removable without changing existing service
  volumes or networks.
- `shared.rbac` changes are additive and covered by legacy plus new role-claim
  tests.
- Patch deployment retains the previous digest on every instance and records a
  rollback job before replacement. A failed post-deploy checker automatically
  requests replacement with that digest.

## Definition-of-done interpretation

“Docker Compose deployment” means the provided host-side demo can start three
teams × two identical service definitions without exposing Docker control to
an application container. “Atomic replace” in Compose means a runtime adapter
swap followed by post-check and deterministic rollback. The optional
Kubernetes adapter adds digest-pinned surge rollout and readiness gating, but
does not install the cluster control plane, CNI, registry or RWX storage. These
limitations are surfaced in operations and security documentation rather than
hidden behind mocks.

## Implementation and verification record

The phases were applied additively in this order. The named paths are the
implemented sources, not design-only placeholders.

| Phase | Material changes | Verification |
|---|---|---|
| 0 — analysis/safety | This gap analysis; isolated database and migration/rollback boundary; baseline legacy test run before implementation | Baseline: `248 passed` |
| 1 — core | `services/attack_defense/{models,repositories,game_engine,flag_service,scoring,api}.py`, `migrations/0001_initial.sql`, mode strategy interfaces | Deterministic flag, expiry, self/cross/duplicate rejection, round transition, ledger idempotency, pause/recovery, RBAC and concurrency tests |
| 2 — symmetric services | `demo_services/vulnerable_notes`, `demo_services/file_vault`, checker/injector adapters, six hardened Compose instances | All six containers healthy; one round issued/injected six flags and recorded the complete checker workflows |
| 3 — scoring | Category-aware ledger/snapshots, public delay, round/Match recalculation and hybrid weighted score events | Live opponent submission awarded +10 once; duplicate/self submissions rejected; finalization produced separate Attack/Defense/Availability totals |
| 4 — patches | OCI inspector, policy state machine, durable runtime jobs, host runner, sandbox/post-check/rollback path, local registry | A digest-pinned patched Notes image passed policy, sandbox flag/function checks and live replacement; failed-deploy rollback is covered by unit tests |
| 5 — operations | Operator/participant APIs, CLI, metrics, evidence, Compose planes, Kubernetes policy example, k6 profile and documentation | Compose config accepted; API process restart recovered the active round; full regression after implementation: `296 passed` |
| Post-MVP — PCAP privacy | Fail-closed classic-PCAP sanitization, delayed/team-rekeyed release, watermark, API/CLI/UI and audit | Parser, privacy, access, delay, integrity and rate-limit tests |
| Post-MVP — Kubernetes runtime | Restricted team/sandbox bundles, explicit-context kubectl adapter, audited reconciliation, readiness-gated patch rollout | Manifest policy, namespace isolation, dry-run/apply command boundary, rollout failure and RBAC tests |
| Post-MVP — HA game engine | SQLite/PostgreSQL compatibility, advisory Match locks, DB clock, shared rate limits, sequenced SSE audit stream and fenced `SKIP LOCKED` runtime jobs | PostgreSQL migration/readiness, two-engine locking, concurrent submission/rate-limit, job claim/fencing tests; local two-replica HAProxy profile |
| Post-MVP — KOTH | Optional symmetric-mode team/service hills, append-only round leases, atomic capture/transfer, functionality-gated scoring, API/CLI/metrics and Live Fire board | SQLite policy/lifecycle/redaction/recalculation tests plus PostgreSQL per-hill concurrent capture serialization |
| Post-MVP — Stealth Mode | Optional delayed incident disclosure, hashed pre-disclosure defender reports, independent attack/detection scoring, visibility floor and role-specific Live Fire projection | Policy/mode, oracle resistance, idempotency, release timing, deterministic score and KOTH delay tests plus PostgreSQL concurrent report serialization |
| UI 1–3 | Role-specific Live Fire shell, battle/attack/defense/patch/operator/observer screens, SSE recovery, topology, command palette, accessibility and responsive tokens | Vitest `17 passed`; TypeScript/Vite production build passed; Playwright `3 passed` at 1920×1080 and laptop viewports; `npm audit` reports 0 vulnerabilities |

The browser regression suite uses typed, deterministic route fixtures. The
screenshots in `docs/ui/screenshots/` were separately captured against the
running API and six real demo service containers.

Latest full regression after PCAP, Kubernetes, HA, KOTH and Stealth additions:
`341 passed, 6 skipped` (the skipped cases require
`ATTACK_DEFENSE_TEST_POSTGRES_URL`). The same six PostgreSQL tests passed
against PostgreSQL 17 in the explicit HA test profile. Live Fire Vitest remains
`17 passed`; the production build and dependency audit passed with 0 reported
vulnerabilities. On the retained 955MB demo database, migration
`0005_metrics_indexes` reduced an observed Prometheus scrape from 13.27 seconds
to 0.14 seconds without rewriting score, audit or checker rows.
