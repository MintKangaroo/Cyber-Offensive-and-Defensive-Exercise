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
| 5 Incident workbench | Three panes, SLA, transitions, assignee, notes, evidence and AAR navigation | Delivered persisted scenario/asset/evidence association and service-scoped SIEM/EDR in the production profile; expand specialist investigation interactions |
| 6 Scenario Studio | Lossless Visual↔YAML, stages, dependencies, points, Blue objectives, multi-doc sources, actual validation/dry run, persisted drafts, guarded publish, embedded inject-campaign authoring | Delivered crossover phase creation, investigation answer keys, executable dependencies, Blue recovery criteria and a scenario-embedded crisis-comms inject campaign (validated by the injects runtime's own rules, launched with referential integrity). The built-in inject template library still has no publish endpoint and rubric grading stays manual; runtime planning-only semantics are explicitly labeled |
| 7 Replay / AAR | One-clock event/asset/ledger/incident/detection/patch projections, milestones, annotations and export | Delivered journal resume, scoped patch/isolation history, scenario-linked incidents and signed >50k replay pages. Authoritative asset checkpoints and distributed cross-service snapshots remain |
| 8 Role workflows | Scoped command views, guided eight-step missions, native Red/Blue/SIEM/EDR and full A/D workbench retained; delayed/stealth engine reused | Complete visual migration of specialist inner pages and the static beginner/competition hubs. Preserve flag, patch, tournament and hidden-information tests |
| 9 AI / training | Optional local assistant, instructor policy, authorized telemetry context, marked suggestions, transparent team completion recommendations | Delivered verified personal attempts, explicit-start elapsed time and deterministic recommendations. Policy-aware hint records and instructor-reviewed defensive rubrics remain before claiming mastery |
| 10 Quality / deployment | Backend regression suite, strict TS, lint, Vitest, Playwright/axe, six frontend builds, gateway image, local startup and documentation | Delivered isolated PostgreSQL HA integration and permanent CI coverage. Production scale soak, complete manual accessibility audit and external acceptance exercise remain |

## Continued delivery and acceptance work

The production profile now enforces receiving-service ownership across collector,
SIEM, EDR, incident, injects, configuration, scoring, scenario, portal, range control,
NOC, observability and AAR. Dangerous direct mutations have durable confirmation and
reason checks. The isolated local compatibility profile remains distinct; it is not
a shared-deployment authorization boundary. Read [SERVICE_SCOPE.md](SERVICE_SCOPE.md)
before production rollout, including scoped sensor credentials and paired Red/Blue
inventory. A/D retains its separate tested security and disclosure model.

Remaining priorities:

1. Delivered: crisis-communications inject campaigns are authored in Scenario Studio
   and embedded in the scenario source, giving injects the durable, re-loadable
   publication contract they lacked. Validation reuses the injects runtime's rules
   (`shared/injects_campaign.py`) and launch (`/command/injects/campaign/launch`)
   binds the campaign to the scenario id. Remaining: the built-in inject template
   library still has no publish endpoint (templates are inline or in source), rubric
   grading is manual by design, and complex campaign/rubric review stays in the
   Injects workspace until that library gains its own publication contract.
2. Delivered: the internal visual migration of the specialist inner pages and static
   hubs is complete. SIEM, the EDR console, the Blue portal and the Red portal were
   moved onto the shared React design system (tokens + Panel/Badge/Button/Empty/Error
   primitives, tests for each — the Red portal keeps its existing guided-logic tests)
   with detection/containment/defensive/offensive semantics and transport preserved;
   the two static hubs (START HERE, Competition) were aligned to the shared palette.
   Advanced workflows and operational detail were kept throughout. Remaining refinement:
   deeper interaction parity for individual specialist views can continue incrementally.
3. Extend the delivered personal attempt/start/pass evidence with policy-aware hint
   usage and instructor-reviewed defensive rubrics. Keep competition scores
   independent of any proficiency estimate and label unavailable measurements.
   Delivered: **policy-aware hint usage records** (progressive per-learner hint reveals,
   an instructor enable/disable policy, `hints_used` in the personal profile) and
   **instructor-reviewed defensive rubrics** (an optional Blue-task rubric, an instructor
   review queue and scoring endpoint, a `review` object in the personal profile). Both
   are kept entirely out of competition scoring. Remaining: optional hint-reveal and
   review-display UI in the Red/Blue portals, and policy-aware AI-hint records once the
   local model is evaluated (priority 6).
4. Add authoritative asset checkpoints and a bounded-memory strategy for very large
   replay archives. The durable journal and 50,003-event pagination tests do not
   constitute unlimited browser capacity or a distributed snapshot guarantee.
   Delivered: **authoritative asset checkpoints** (the collector folds the journal into
   a per-asset checkpoint frozen at a `seq`/`revision`, materializing only the derived
   asset-state, with create/read endpoints and a command projection) and **bounded-memory
   replay** (the Control Tower holds a sliding window of the most recent 20,000 events
   and anchors asset state on the nearest checkpoint, instead of accumulating every
   page). A distributed cross-service snapshot remains explicitly out of scope, and the
   bounded window's pre-window incident/score/config detail is labelled as not
   reconstructed.
5. Run a full instructor-led acceptance exercise and production-scale soak on the
   intended hardware, including restoration and outages. PostgreSQL replica tests now run locally and in CI.
   The isolated Docker scope drill and browser fixtures have narrower stated scope.
6. Complete manual accessibility and keyboard review of specialist workflows and
   evaluate the selected local AI model for grounding, hints policy and telemetry
   prompt injection before enabling it. AI remains disabled by default.
   Code-side progress: automated `axe-core` structural accessibility checks now guard
   all four specialist dashboards (SIEM, EDR, Blue, Red) in CI, and fixed the landmark
   and ARIA-attribute regressions they found. The manual keyboard/screen-reader review
   and the local AI model evaluation still require human/operator work and remain open.

Unknown telemetry remains unavailable. Existing native capabilities and scoring
rules remain available within their established authorized range boundaries.
