# Next-generation changelog


## 2026-09-11 — EDR console adopts the command design system

- Migrated the EDR console (App three-pane shell + HostList, ProcessTree,
  AlertsPanel) off its standalone Tailwind palette onto the shared design system
  (tokens + Button, StatusBadge, EmptyState). Removed Tailwind/PostCSS; EDR-specific
  layout — the workspace panes, host list, the pstree-style process explorer and the
  severity-accented detection cards — now lives in `src/index.css` with no hard-coded
  colors. Second of the specialist inner-page migrations (roadmap priority 2).
- Preserved containment and detection semantics exactly: host Isolate/Unisolate and
  process Kill still require an audit reason and confirmation; the asynchronous
  KillCommand result and warning surface as before; the pstree connectors, collapse,
  flagged/critical highlighting and Korean asset labels are unchanged. The five
  severity strings keep their labels; only colors move onto five distinguishable
  tones (`severity.ts`). Transport (`api/client.ts`/`types.ts`) is untouched —
  5s polling, WebSocket reconnect backoff and base-URL resolution behave as before.
  The isolate-failure `window.alert` became an inline error line (no behavior loss).
- Added the EDR console's first automated tests: `severity.test.ts` and
  `dashboard.test.tsx` (host isolation, process kill and process-tree rendering),
  run by the specialist-dashboards CI job via `npm run test --if-present`.

Validation: **8 Vitest tests pass**, `tsc -b` + Vite build pass, no Tailwind
references remain. No backend or transport contract changed.


## 2026-09-11 — SIEM specialist page adopts the command design system

- Migrated the SIEM analyst workspace (App shell + Discover, Alerts, AttackCoverage,
  SourceHealth) off its standalone Tailwind palette onto the shared CYBER RANGE
  COMMAND SYSTEM tokens and primitives (Panel, StatusBadge, Button, EmptyState,
  ErrorState). Removed Tailwind/PostCSS; SIEM-specific layout now lives in
  `src/index.css` with zero hard-coded colors. This is the first of the specialist
  inner-page migrations (roadmap priority 2), one dashboard per change.
- Preserved detection semantics exactly: numeric severity 0–4 keeps its
  INFO/LOW/MEDIUM/HIGH/CRITICAL labels and the 2/3/4 filter thresholds; only colors
  move onto five distinguishable design-system tones (`severity.ts`). The transport
  layer (`api/client.ts`/`types.ts`) is unchanged — polling cadences (alerts/source
  5s, coverage 15s), WebSocket reconnect backoff, base-URL resolution and the
  open→ack→closed alert lifecycle all behave as before.
- Added the SIEM dashboard's first automated tests: `severity.test.ts` (pure mapping)
  and `dashboard.test.tsx` (view integration with the real polling hook and a mocked
  network layer), run by the existing specialist-dashboards CI job via
  `npm run test --if-present`. Instructor-only fields (`vuln_id`/`trace_id`/`team_id`)
  remain unexposed; the workspace still shows only detections, coverage and rule ids.

Validation: **13 Vitest tests pass** (6 severity, 7 view), `tsc -b` + Vite production
build pass, no Tailwind references remain. Error and loading states, previously
silent, now use the shared ErrorState/EmptyState. No backend or transport contract
changed. The user-owned Compose override was untouched.


## 2026-09-11 — Injects campaigns become first-class scenario authoring

- Gave the injects subsystem the publication contract it lacked: a campaign is now
  embedded in a scenario source (`injects_campaign:`) and published through the
  existing lossless scenario file flow, so campaign authoring is faithful (durable,
  re-loadable, validated) instead of an imperative runtime POST. The campaign's
  `scenario_id` binds to the scenario id, replacing the previous free-form string
  with referential integrity.
- Added `shared/injects_campaign.py` as the single source of truth for a valid
  campaign. The injects runtime re-exports its `CHANNELS`/`TRIGGER_EVENTS` so the
  execution and authoring rules can never drift; Scenario Studio validation calls
  `campaign_issues` so anything the runtime rejects is an error at authoring time,
  with unknown templates, forward triggers and empty inline injects as warnings.
- Extended Scenario Studio with a lossless visual campaign editor (spec ids,
  templates, channels, inline subject/body, deadlines, schedules, answer/deadline
  triggers and per-spec manual-grading rubrics). Existing scenario data, comments
  and unknown fields are preserved; the Injects workspace keeps complex library and
  rubric-review workflows.
- Added `GET /studio/campaign/{sid}` (instructor) to extract and validate a
  published scenario's embedded campaign, and `POST /command/injects/campaign/launch`
  to load it into the injects service with the scenario id attached and a durable
  requested/launched/rejected audit. Invalid campaigns are refused before launch.
- Honest limits recorded: the built-in inject template library still has no publish
  endpoint (templates are inline or in source) and rubric grading remains manual.

Validation: **611 Python unit tests passed** (PostgreSQL-dependent integration runs
in CI), including 24 new campaign-authoring/Studio/command tests and the unchanged
injects runtime bad-trigger contract. **57 Command Vitest tests** (3 new
campaign fidelity cases) and **18 Playwright flows** (new lossless campaign authoring
flow) passed. Control Tower TypeScript build, ESLint and the six-app gateway build
were re-run. No existing tests were removed; the user-owned Compose override was
preserved.


## 2026-09-09 — Crossover Studio and personal training evidence

- Added visual crossover phase creation with explicit IDs/dependencies, Red/Blue
  actors, investigation submission/answer fields, phase evidence capture, final
  stage controls and single-scenario Blue recovery objectives.
- Applied typed evidence criteria explicitly; pending edits block save/validation
  and mode changes. Existing shipped YAML documents receive fidelity regression
  coverage. Planning fields are distinguished from executable runner conditions.
- Corrected investigation-only validation and numeric phase projection; added
  per-phase dependency/identity checks and honest completion-rule diagnostics.
- Added verified personal attempt attribution to the existing portal audit, explicit
  idempotent practice starts, scoped personal coverage/history and deterministic
  next-exercise recommendations. Kept competition scores and legacy team APIs.
- Prevented nested submission fields from overriding the Red grader's team;
  routed Blue challenge navigation to the defensive catalog.
- Resolved effective included-router templates under pinned production FastAPI
  while preserving exact role/method grants and compatibility with flattened routes.
- Provisioned PostgreSQL in CI so all six replica/concurrency/Stealth tests run.
  Extended the isolated Docker drill to the real portal and personal-training API.
- Updated README, architecture decisions, audit/roadmap and contract/deployment docs;
  added [Studio guide](SCENARIO_STUDIO.md) and [personal evidence guide](PERSONAL_TRAINING.md).

Validation: **687 Python tests passed with pinned runtime dependencies and PostgreSQL,
no skipped tests** (existing dependency/test-key warnings remain). **54 Vitest tests**
include all shipped scenario source fidelity cases; **17 Playwright flows** include
crossover authoring, pending criteria, keyboard/tablet accessibility and personal
training/fallback states. TypeScript, ESLint, the six-app gateway build and secret
scan passed. **44 real HTTP Docker checks** passed with fresh credentials and data.
User-owned Compose overrides and the running training stack were preserved.

Remaining: specialist inner-page design migration, integrated complex inject/rubric
editing, policy-aware hint records and reviewed defensive assessment, authoritative
asset checkpoints, model evaluation and intended-hardware acceptance/soak testing.

## 2026-09-09 — Receiving-service scope and durable operations

- Added strict production HTTP/WS/SSE role, team and exercise enforcement, including
  JWT revocation checks and sensor-specific credentials. No service master is sent
  to lab twins. Blue SOC navigation opens only with verified scoped service support.
- Persisted incident, inject, SIEM and EDR ownership; verified alert promotion,
  retained automatic incident deduplication and distinguished actor score attribution
  from defensive asset ownership in paired Red/Blue exercises.
- Added transactionally durable event stream cursors and signed snapshot-bound
  replay pages. Control Tower loads beyond 50,000 events and detects stale cursors.
- Reconstructed scenario-attributed incidents and actual configuration audit changes
  at playback time. AAR selects exercise evidence rather than platform aggregates.
- Added direct dangerous-action confirmation, reason and persistent intent/outcome
  audit. Existing instructor panels use shared confirmation dialogs. EDR reset keeps
  its action audit, and unavailable emergency state stays unknown.
- Fixed personal contribution aggregation mixing the same team across exercises;
  strict portal submissions use authenticated identity rather than supplied subjects.
- Added an isolated production-profile Docker contract drill with temporary
  credentials, no host ports and no changes to the running training stack.

Validation: **657 Python tests passed, 6 PostgreSQL-dependent skips**; 34 direct
service scope tests are included. **35 Command Vitest tests, 12 Playwright flows,
19 existing LiveFire tests** passed. Command TypeScript/ESLint, LiveFire build, the
six-application gateway Docker build, nginx syntax and the secret scan passed.
The isolated production Docker drill passed **35 actual HTTP checks**, including
scoped sensor forwarding and denial through the ingress proxy. Existing training
containers and the user-owned Compose override were preserved.


## 2026-09-09 — Cyber Range Command migration

- Audited the actual repository before replacing the legacy Control Tower HTML.
- Added the local CYBER RANGE COMMAND SYSTEM token/component package; integrated a
  consistent workspace entry bar into LiveFire, Red, Blue, SIEM and EDR.
- Built a strict-TypeScript React Control Tower with capability navigation, global
  search, notification grouping, high contrast, War Room, responsive safety controls,
  role-aware login and on-demand advanced inspectors.
- Added an authenticated Instructor API command projection: fixed upstream allowlist,
  JWT revocation verification, team scope checks, sanitized delayed observer evidence,
  partial-source status and reasoned/audited instructor commands.
- Connected the existing 11 ICS/OT sectors to observed event state. Added searchable,
  virtualized events, pause, pins, presets, raw evidence and asset/replay navigation.
- Added incident queue/investigation/context panes using the existing lifecycle,
  assignment, notes, SLA and audit contracts.
- Added lossless source authoring, existing-schema validation/dry run, private drafts,
  multi-document revision checks, guarded publish and persistent authored sources.
- Added synchronous replay projections, source-ledger charts, observed milestones,
  instructor annotations and AAR JSON/print export. Missing history stays unknown.
- Reused existing A/D projections, disclosed scores and native competition actions.
  No flag, score, stealth, delayed disclosure, sandbox or challenge solution semantics
  were changed.
- Added optional local AI suggestions with instructor policy and role-authorized
  context. Added transparent team completion recommendations without AI grading.
- Generated 19 Higgsfield brand assets, recorded prompts/provenance, and optimized
  web delivery. No generated image supplies telemetry or operational UI controls.
- Fixed health scrapes treating non-success HTTP as healthy, unknown emergency-stop
  reads becoming false, ignored release failures, AAR downstream auth forwarding,
  and accidental submit behavior in shared confirmation buttons.
- Added optional bounded collector replay, source-aware AAR availability, shared
  Docker build paths, authored-scenario persistence and command CI/browser checks.

## Validation record

The original backend baseline was **574 passed, 6 skipped**. The expanded backend
suite is **623 passed, 6 skipped**. The skips require PostgreSQL integration state;
the existing three warnings concern multipart/Pydantic declarations.

Control Tower has **34 Vitest tests** and **11 Playwright workflows**, including
keyboard navigation, 5,000-event virtualization, incident transitions, YAML fidelity,
replay reconstruction, observer restrictions, degraded sources, mobile emergency
controls, cancellation and automated accessibility checks. Production TypeScript
build and ESLint are required. Existing LiveFire (19) and Red Portal (11) tests and all five specialist
builds remain in the verification matrix. Gateway Docker build and Compose schema
validation are required before release. See the commit/CI results for execution.

These checks do not constitute a completed production soak, manual accessibility
certification, or full real-infrastructure exercise. Remaining work is tracked in
`NEXTGEN_ROADMAP.md`, including existing service-level authorization gaps.

Dependency validation also updated the older specialist Vite/React-plugin toolchains
and patched compatible transitive packages. The Command production dependency
audit reports no vulnerabilities. Vitest's development mock-server advisory remains
moderate; test scripts use `vitest run`, and no Vitest UI server is deployed.

The final local regression run passed 623 backend tests (6 PostgreSQL-dependent
skips), 34 Command unit tests, 11 Command browser workflows, 19 LiveFire tests,
and 11 Red Portal tests. All six React production builds and the Command ESLint
check passed. No existing tests were removed. Browser fixtures are isolated under
`dashboards/control-tower/e2e` and are excluded from the production source bundle.
