# Next-generation repository audit

Date: 2026-09-09. Baseline: the existing local checkout of
`MintKangaroo/Cyber-Offensive-and-Defensive-Exercise`. This audit was written
before implementation. A pre-existing `docker-compose.override.yml` change
extends local authentication lifetime; it is outside this migration.

## Scope and evidence

Inspected README, CONTRACTS, INTEGRATION, SECURITY, documentation index and
architecture/operations/security/UI specifications; inventoried all application,
service, shared, scenario, challenge and test directories. Followed the actual
implementations of authentication, gateway routing, collector streams, scoring,
scenario loading/authoring/running, incidents, injects, AAR, observability, range
control, challenge grading, digital twins and attack/defense visibility.

The checkout contains 15 scenario YAML files (some contain multiple documents),
74 Python test files, five React workspaces, and three standalone HTML dashboards.
Documentation includes older implementation proposals and dated validation counts;
these are not substitutes for running current tests. `INTEGRATION.md` still describes
two repositories and development token examples despite the completed monorepo merge.

## Current architecture

* Python/FastAPI services run through Docker Compose. The nginx gateway serves
  workspaces under `/start`, `/control`, `/ops`, `/red`, `/blue`, `/blue/siem`,
  `/blue/edr`, and proxies fixed internal services under `/api/*`.
* `scripts/training_environment.py` preserves the one-command `make training-up`
  workflow: builds services, bootstraps the local competition, builds React apps,
  and serves dashboards on local ports. Control Tower currently serves HTML on 5180.
* Twins emit contract events to the event collector with service authentication.
  The collector deduplicates to SQLite, batches writes, forwards to scoring with
  retries/DLQ, and broadcasts WebSocket and topic SSE messages.
* SIEM normalizes application/protocol/Suricata/Zeek signals; EDR ingests agent
  process telemetry, maintains alerts, and queues authorized containment actions.
  Config Service owns patch/quarantine/killswitch state. NOC and recovery watcher
  establish actual recovery from compromise, patches and consecutive health checks.
* Scenario Engine loads single and crossover YAML, applies initial vulnerability
  state, enforces stage/phase dependencies, packages evidence and awards chain bonuses.
  Instructor API orchestrates scenario, score and event actions with SQLite audit.
* Incident Service persists alert promotion, assignees, notes, lifecycle and SLA.
  Inject Service handles library, dispatch, response deadlines, rubrics and campaigns.
  AAR assembles events, scores, detection coverage, incident metrics and inject results.
* Attack/Defense has a separate, mature engine: membership-scoped JWTs, rounds,
  opaque HMAC flags, idempotent append-only score ledger, functional/SLA checkers,
  digest-pinned patch validation/rollback, runtime workers, KOTH, stealth, tournament,
  sanitized PCAP and broadcast projections. Retain its tested mode boundaries.

## Frontend architecture and duplication

React 18 + strict TypeScript + Vite are already established. Live Fire uses Zustand,
custom typed clients, a legacy exercise view, an extensive attack/defense application,
and tested broadcast layouts. Red Portal includes a guided beginner mode and an
authorized local target gateway. Blue Portal, SIEM and EDR each have separate clients,
navigation, styles, status rendering, error handling and authentication assumptions.

Control Tower is a 485-line HTML/CSS/script page. It maintains an imperative event
feed, score/safety/incident panels, nine-sector event-derived states and actions.
START HERE and Competition are also standalone pages. Do not remove these working
entry points or move their ports without migrating the startup/build/gateway paths.

Duplicated patterns: host/port inference, bearer headers, fetch helpers, loading/error
state, relative gateway URLs, cards, badges, tabs, modals, score tables, WebSocket/SSE
reconnect loops, and keyboard commands. Existing Live Fire palette, bounded event
buffer and competition components are useful precedents, not candidates for a rewrite.

## Contracts to retain and extend

| Capability | Existing source and contract | Decision |
|---|---|---|
| Identity | `shared/rbac.py`, Auth `/auth/login`, `/auth/me`, `/auth/refresh`, `/auth/verify` | Retain roles and JWT/static token compatibility; resolve identity on server |
| Events | `shared/event_schema.py`; `/events`, `/replay/events`, `/stream`, `/ws` | Preserve event IDs, epoch seconds, metadata and scoring semantics |
| Scores | `/scores`, `/scores/history`; A/D scoreboard/ledger | Never recompute authoritative scores from event-type guesses |
| Assets | twin services, `shared/vuln_catalog.json`, NOC/config/events | Inventory is metadata; unknown health is not secure/healthy |
| Incidents | `/incidents`, `/{id}`, `/from-alert`, `/transition`, `/note`, `/assign`, `/aar` | Retain server state machine and audited timeline |
| Scenarios | `/scenario/list`, `/validate`, `/lint-all`, `/{id}/phase-clock` | Extend with lossless source retrieval/drafts; reuse loader/linter |
| Replay/AAR | `/replay/events`, `/report/aar`, `/report/timeline`, PDF | Reconstruct only observed historical state; identify source gaps |
| Safety | `/safety/status`, emergency-stop/release; `/ranges/{id}/reset` | Use orchestrated reset, explicit reason/confirmation and audit |
| Observability | `/observability/summary`, Prometheus `/metrics` | Surface measured scrape state; unavailable counters stay unavailable |
| Competition | `services/attack_defense/api.py`, `dashboards/livefire/src/attackDefense` | Reuse projections, especially delayed/stealth disclosure |

Database event metadata can arrive as JSON text; live SSE metadata is an object.
Clients must normalize both, validate network payloads, and preserve unknown fields.
The event `Asset` enum is older than the actual sector inventory; do not use it to
drop new-sector telemetry. Roles currently are instructor, operator, competitor,
red, blue, observer. There is no `admin` role; do not invent a privileged UI role.

## Realtime, scalability and correctness risks

1. Shared SSE defaults to 1,000 messages; Collector configures a 2,000-message in-memory replay ring and slow-subscriber queues.
   Cursor history is lost on service restart; durable replay is a separate API.
2. Legacy observer visibility drops messages that are too young instead of scheduling
   their delayed delivery. A/D has its own more complete disclosure behavior.
3. Legacy WebSockets and event/replay read APIs do not consistently enforce identity
   or team scoping. `require_read` is optional and accepts all authenticated roles.
   SIEM/EDR/incident reads therefore cannot be assumed safe for Red/observer command
   views merely because gateway authentication succeeded.
4. Control Tower uses EventSource without bearer headers in direct mode, builds HTML
   with unescaped telemetry, ignores most fetch errors and lacks bootstrap history.
   It treats any HTTP <500 health response, including 401/404, as alive.
5. Control Tower runs multiple polling loops despite a stream; scores are always
   requested for `default`; its ICS map omits satellite/enterprise and starts empty.
6. Live Fire derives secure state from unrelated events and initially calls every
   asset secure. A new canonical reducer must preserve compromise until evidence of
   containment/recovery, distinguish unknown, and sort/dedupe deterministically.
7. AAR best-effort requests omit downstream auth and can turn unavailable sources
   into empty sections. Cross-scenario incidents/alerts need explicit attribution.
   Replay lacks historical incident/patch/score reconstruction in the existing UI.
8. SQLite single-node limits, unbounded legacy replay responses, collector forwarding
   tasks and in-memory streams constrain horizontal scale. Do not claim HA without
   running the separate A/D PostgreSQL/coordination suite.

## Security boundaries and non-regression requirements

Fail closed for new command endpoints even when legacy monitoring permits public
reads. A navigation item is a capability hint, not authorization. Scope Blue data
by membership; reject requests that cannot establish scope. Instructor-only source
documents may contain answers and initial vulnerability state. Do not publish them
through global search or observer views. Keep A/D competitor/operator/public routes
separate; never use operator telemetry to decorate a participant page.

Preserve: HMAC flags and grading, challenge anti-cheat, dynamic scoring, append-only
ledger idempotency, delayed scoreboard/stealth disclosure, tournament membership,
patch namespace/registry allowlists, image digests, management-plane runtime workers,
internal twin networks, fixed target gateway, no Docker socket in API containers,
service ingest tokens, killswitch, audit records, baseline reset, and all beginner
and advanced workflows. Never add a user-controlled arbitrary upstream URL.

Existing gaps to repair carefully: new safety UI needs a nonempty reason and a
separate confirmation; old reset clears only four services and uses an incorrect
portal path. Range Control already has an eight-service orchestrated reset. A failed
killswitch read currently becomes false, and release can report success despite an
upstream HTTP error. Authentication revocation is verified in Auth/gateway, while
shared JWT decoding alone does not consult revocation. New sessions must consider it.

## UX, design and accessibility

* There is no shared app shell or entity navigation. Operators must remember ports,
  tokens and separate layouts. Blue investigation needs queue/workspace/evidence in
  one view; beginner briefing/task/defense/result should stay guided.
* Inconsistent navy palettes, fonts, severity meanings, spacing and component
  density obscure role and system state. Some controls are excessively monospace.
* Legacy Control Tower has no semantic navigation, modal focus management or visible
  keyboard focus system. Several input fields use placeholders as their only label.
  Mobile hides event topics and relies on colored bars. War Room uses enlarged text
  but does not provide a coherent topology or fullscreen workflow.
* No rich incident workbench, fidelity-preserving visual authoring, synchronous
  replay, scoped global search, grouped notifications or optional grounded assistance.
* No shared accessible empty/loading/stale/degraded/unauthorized states. Motion and
  color must be accompanied by text and reduced-motion/high-contrast alternatives.

## Test baseline and missing coverage

Existing Python tests cover contracts, protocols, scoring, incident pure model,
authoring, AAR, safety, beginner scripts and broad A/D security. Live Fire Vitest
covers pure UI/broadcast/process logic; Playwright covers competition roles and
snapshots. Control Tower has no React/component/accessibility suite. CI builds only
Live Fire in its dashboard job; supply-chain checks visit the other React apps.

Before implementation, the full Python suite was started with its output preserved
outside the repository. Results and all new verification belong in NEXTGEN_CHANGELOG.
Needed tests: command API identity/role/team restrictions, unauthenticated denial,
upstream partial failures, safe action reason/audit, no raw solution disclosure,
stream parser/chunk boundaries/cursors/reconnect/cleanup, bounded event rendering,
lossless YAML and invalid/dependent stages, historical reconstruction without future
state leakage, incident conflicts, command palette focus/keyboard, mobile and high
contrast accessibility, startup/gateway production builds.

## Migration decision

Extend the existing Instructor API with an explicit command projection boundary and
fixed upstream allowlists. Modernize Control Tower into React at its existing entry
point. Share a local source package for tokens, UI primitives and transport; adopt
it incrementally in existing workspaces. Keep specialist A/D and offensive workbenches
intact and reachable. Add capabilities only where backed by contracts or an explicit,
tested additive API. Record limitations instead of faking completeness or telemetry.


## Follow-up: service boundaries and retained history (2026-09-09)

The initial findings above describe the pre-migration repository. The production
profile now applies receiving-service identity/ownership checks, scoped sensor
credentials, persistent incident/inject/SIEM/EDR ownership and direct dangerous
operation confirmation/audit. The collector has a durable journal and signed replay
pages; Command reconstructs owned incident/configuration history. The audit's local
compatibility warning still applies when strict scope is disabled. Implementation,
limits and tests are specified in [SERVICE_SCOPE.md](SERVICE_SCOPE.md); uncompleted
visual authoring, specialist UI, personal training and acceptance work remains in
[NEXTGEN_ROADMAP.md](NEXTGEN_ROADMAP.md).
