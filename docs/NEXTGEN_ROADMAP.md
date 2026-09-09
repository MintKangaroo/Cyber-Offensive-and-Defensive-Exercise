# Next-generation delivery and remaining work

2026-09-09. This is an incremental migration, not a claim that the entire requested
national exercise platform specification is complete.

| Phase | Delivered / retained | Remaining work and acceptance condition |
|---|---|---|
| 0 Audit | Repository inventory, service/UI/security/contract assessment before refactoring | Revisit as legacy boundaries change |
| 1 Shared foundations | Central tokens, transport, accessible primitives, React workspace bars | Extend tokens into each specialist page during its own regression-tested migration |
| 2 App shell | Server-capability navigation, identity, global search, notifications, contrast/density, mobile navigation | Individual specialist routes still retain their original interfaces |
| 3 Control Tower | React flagship, source availability, safety context, priority incidents, War Room | Full elapsed/phase coverage depends on retained start/phase evidence; no invented clock |
| 4 Live / twin | Existing 11-sector inventory, evidence-driven state, inspector, stage evidence, bounded SSE and virtual events | Port-level topology and authoritative current asset snapshots need an explicit backend contract; causal graph edges need correlation evidence |
| 5 Incident workbench | Three panes, SLA, transitions, assignee, notes, evidence and AAR navigation | Add persisted scenario/asset/alert association and Blue-scoped SIEM/EDR query contracts before exposing global SOC tools to teams |
| 6 Scenario Studio | Lossless Visual↔YAML, stages, dependencies, points, Blue objectives, multi-doc sources, actual validation/dry run, persisted drafts, guarded publish | Advanced crossover phase creation, arbitrary inject/rubric/recovery rules still use existing YAML/Injects tools. Expand controls against real schema fields, with fidelity tests |
| 7 Replay / AAR | One-clock event/asset/ledger/incident/detection/patch projections, milestones, annotations and export | Durable asset checkpoints, patch state history, scenario-linked incidents and paginated >50k replay are required for complete time travel. Some AAR aggregates remain platform-wide |
| 8 Role workflows | Scoped command views, guided eight-step missions, native Red/Blue/SIEM/EDR and full A/D workbench retained; delayed/stealth engine reused | Complete visual migration of specialist inner pages and the static beginner/competition hubs. Preserve flag, patch, tournament and hidden-information tests |
| 9 AI / training | Optional local assistant, instructor policy, authorized telemetry context, marked suggestions, transparent team completion recommendations | Individual proficiency needs attributed attempts, hints, duration and defensive rubrics. No opaque AI score or fabricated mastery estimate is implemented |
| 10 Quality / deployment | Backend regression suite, strict TS, lint, Vitest, Playwright/axe, six frontend builds, gateway image, local startup and documentation | Production scale soak, PostgreSQL integration environment, complete manual accessibility audit and external acceptance exercise |

## Required production security follow-up

The new command endpoints fail closed. Several pre-existing service reads and
WebSockets remain broader than this boundary: collector event/replay reads, SIEM,
EDR, incident, source authoring/progress, and some aggregate metrics need a consistent
service-level scope policy. `OBSERVER_READ_ENFORCE` authenticates reads but does not
by itself grant appropriate team-level isolation. Hiding navigation cannot fix that.
Do not expose independent legacy service ports to untrusted networks. Run the
existing isolated range deployment and gateway/network controls, and validate each
service's authorization before treating a shared deployment as multi-tenant.

Priority follow-up:

1. Define a compatible team/exercise ownership contract for SIEM alerts, EDR hosts,
   incidents and replay checkpoints. Migrate service reads and WebSockets with
   positive and negative role/team tests; preserve A/D delayed/stealth projections.
2. Gate all legacy instructor mutation paths consistently with reason, confirmation
   and durable audit, including direct service access. Command actions already do
   this; independent legacy URLs remain a separate migration.
3. Add durable stream resume/checkpoints and server-side replay pagination. Validate
   continuous ingestion and source failures under measured exercise load, including
   restarts. The current bounded UI is not a platform throughput guarantee.
4. Validate recovery objectives, score history and AAR linkage in a full live exercise
   on the intended infrastructure. Test fixture screenshots and mocked browser tests
   demonstrate UI behavior, not production telemetry or a complete live-range drill.
5. Evaluate the selected local AI model's grounding and training policy, including
   prompt injection from log content. Keep AI disabled until that evaluation passes.

These items are intentionally visible. Unknown data remains unavailable; native
workflows remain accessible where their established security model permits them.
