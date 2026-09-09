# Service ownership and durable replay

This rollout extends the existing services. The isolated local training profile is
compatible with its established single-range workflow. The production Compose
profile enables `RANGE_SCOPE_ENFORCE=true`; legacy local mode is not a multi-tenant
security boundary. The Attack/Defense engine retains its own tested projections,
score rules, sandbox and delayed/stealth disclosure.

## Identity and data ownership

Direct HTTP, WebSocket and SSE requests are authenticated by the receiving service.
Human JWTs require signature, expiry and Auth revocation verification. Auth failures
close access. Long-lived connections verify the session again at least every 15
seconds, including while idle. Service credentials are restricted to internal
reads/ingest; they do not authorize instructor resets.

Blue and Red JWTs need both `team_id` and `match_id`. On the legacy exercise plane,
`match_id` selects the actual scenario/exercise ID. Shared static team tokens lack
this membership and cannot read scoped production records. Instructor static tokens
remain supported. Instructor aggregates, authoring and administrative operations
remain instructor-only. Observers receive allowlisted public event fields after at
least 30 seconds; requesting a shorter delay does not remove this bound.

The operator assigns sensor assets through `RANGE_ASSET_SCOPES`. For a paired
exercise, an example is:

```dotenv
RANGE_ASSET_SCOPES={"ground_station":{"team_id":"blue_alpha","red_team_id":"red_alpha","scenario_id":"TRAINING-01"}}
```

`team_id` owns the defensive asset. Optional `red_team_id` identifies the assigned
attacking team; without it a shared-team training exercise uses `team_id`. This
separates the event actor's scoring team from `defender_team_id`. Blue can inspect
attacks on its asset; Red only receives its own Red activity. Neither request text
nor a sensor can assign another asset's ownership. SIEM/EDR ownership is stamped
from operator inventory, not untrusted log fields. Asset names must be distinct
across concurrent exercise instances. Reusing an EDR host in another exercise
requires the existing confirmed reset; it cannot silently transfer historical data.

Incident and inject schemas add nullable `scenario_id`. SIEM events/alerts and EDR
hosts also retain ownership. Unknown historical ownership is instructor-only; no
migration guesses an exercise from a team name. Blue promotion verifies a real
scoped source alert. SIEM automatic promotion retains rule/asset deduplication,
adds exercise/team isolation to that key when available, and keeps the real alert
ID as `evidence_alert_id`. Notes, assignment, SLA and lifecycle transitions use the
same case boundary. Portal team claims and personal attribution come from identity
in strict mode; private anticheat and individual aggregates remain instructor-only.

## Sensor credentials and startup

Run the existing `./scripts/gen_secrets.sh` before production startup. It now invokes
`scripts/gen_sensor_tokens.py`, which derives `RANGE_AGENT_<ASSET>` credentials from
the service secret and updates the protected `.env` file. Rotating the service
secret requires rerunning this step and recreating the affected containers.

Each twin receives only its own `RANGE_AGENT_TOKEN`. It never receives the service
master. The `RangeAgent` credential permits its own event/snapshot reports, own
patch/isolation reads, emergency-stop state, and own process-command polling/ack.
It cannot read global events, other hosts, audit records or instructor controls.
Production ingest proxy forwards this scoped identity and rejects the old anonymous
fallback. Isolated legacy training retains the existing ingest proxy behavior.

An unassigned sensor is visible to the instructor with unavailable team ownership;
it cannot fabricate membership from telemetry. Configure inventory before starting
a shared exercise. The inventory is deployment configuration, not a new automatic
asset discovery or network isolation mechanism. Keep the existing internal twin
networks, gateway, egress restrictions and absence of Docker socket mounts.

## Dangerous operations

In strict mode direct reset, emergency-stop/release, scenario start/termination,
baseline reset verification and match deletion require JSON `confirm: true` and a
nonblank reason of 3–2000 characters. Command and native instructor screens provide
explicit confirmation; cancellation sends no operation. A durable intent is written
before execution to `DATA_DIR/security-actions.jsonl`, followed by the HTTP outcome.
Storage failure prevents execution. These records survive service resets; EDR also
retains its existing action audit table. An HTTP response is not proof that every
downstream service succeeded: Command retains its explicit partial-reset result.

## Replay and configuration history

The collector appends an SQLite journal entry in the same transaction as each new
event. Deduplicated event IDs do not create a second journal entry. Safety/phase and
score notices are also journaled. The existing SSE bus wakes readers; readers use
the journal to resume after restart or a dropped queue notification. Sequence IDs
survive reset. A reset/retention gap emits `stream-gap`; Command reloads retained
evidence. Non-streamed source reconciliation and observer snapshots remain bounded.

`GET /replay/page?scenario_id=&limit=&cursor=` provides chronological, signed pages.
Its cursor binds the scenario, identity and fixed journal upper bound. A late arrival
belongs to the next snapshot, so it cannot move the current page boundary. A reset
or retention change invalidates an in-progress replay with HTTP 409. Pages contain
`events`, `next_cursor`, `complete` and `snapshot`. The existing `/replay/events`
contract remains available. Command uses `/command/replay?paged=true` and
`/command/replay/page` to load retained history beyond the former 50,000-event window,
with visible progress, cancellation and malformed-page checks.

`GET /config/history?scenario_id=` exposes actual patch/isolation audit changes whose
ownership was recorded when the action occurred. Replay applies only changes and
incident timeline entries at or before its cursor. Initial configuration is unknown
without an earlier record. AAR source requests now select the exercise, including
alerts, incidents, injects and integrity evidence. Historical unowned records are
not silently mixed into that report.

This is retained evidence reconstruction, not a claim of distributed asset
checkpoints or an unlimited browser memory budget. Authoritative port topology,
long-duration load validation and complete cross-service snapshot checkpoints
remain roadmap items.

## Verification

`python3 -m pytest tests/unit/test_service_scope.py -q` covers positive/negative
roles, paired Red/Blue ownership, query spoofing, sensor restrictions, incident and
inject workflows, session revocation, confirmed actions, audit failure, journal
restart/dedup/reset, and complete pagination over 50,003 events.

`python3 scripts/smoke_service_scope.py` builds a separate temporary Docker project
from the production configuration. It uses fresh credentials, tmpfs data, an
internal network and no host ports. Its actual HTTP drill covers Auth login and
revocation, sensor ingest, scoped EDR/incident operations and confirmed safety.
Only that temporary project is removed. It does not reset the running training
stack and does not claim a full physical range isolation or load certification.


## Personal training and included-router compatibility

The portal now records verified personal attribution on evaluated submissions and
provides membership-bound `/portal/training/me` and explicit practice-start routes.
These new reads/writes independently fail closed even in the compatibility profile;
verified attempt capture requires scope enforcement. See [PERSONAL_TRAINING.md](PERSONAL_TRAINING.md).

Receiving-service authorization supports both flattened routes and the included
router contexts used by the pinned production FastAPI version. Effective prefixes,
route order and HTTP methods are matched before applying the exact grant table.
A participant grant never extends to a global sibling/export route. The isolated
Docker drill includes the real portal router, grading, personal records and revocation.
