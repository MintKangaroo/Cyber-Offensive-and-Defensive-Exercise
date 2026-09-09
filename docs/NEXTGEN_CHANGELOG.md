# Next-generation changelog

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
