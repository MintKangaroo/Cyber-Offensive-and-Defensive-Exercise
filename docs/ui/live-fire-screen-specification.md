# Live Fire Screen Specification

## Implemented

### Global shell

Live Match Header, role navigation, match selector, login, connection
degradation, urgent count and Ctrl/Cmd+K command palette.

### Competitor

- Battle Overview: score strip, own-service cards, public opponent×service
  target matrix and categorized event feed. It does not claim live reachability
  until the server exposes authoritative connectivity probes.
- Attack Console: keyboard-first multi-line submission, local format validation,
  queue, masking/privacy mode, generalized rejection and automatic focus return.
- Defense/Services: service posture, digest, last check, detail panel and patch
  history. No fabricated graphs are rendered when samples are absent.
- Patch Operations: team image submission plus staged validation/deployment
  pipelines.
- Scoreboard: raw categories, provisional and delay disclosure.

### Operator

- Command Center: global ribbon, team×service matrix, round controls,
  infrastructure summary and incident queue.
- Matrix cells open an operational service detail with checker time and pinned
  image. Restart/rollback requires an audit reason plus typed service-name
  confirmation and is queued through the trusted runtime boundary.
- Risk actions open a modal, require an audit reason, trap focus and explain
  impact. Match stop additionally requires the match name.
- Checker, flag, evidence, patch and scoring destinations use role-only
  navigation and server-authorized APIs.

### Observer

Broadcast-safe scoreboard, match clock, aggregate healthy/total service posture
and major events. The public service summary has no team mapping. Observer
views never receive endpoints, flags, checker evidence, patch image references
or management details.

## Responsive behavior

- 1920×1080: fixed navigation, three-part header, two-column operational page.
- 1440/laptop: wrapped utility header, compact navigation, single-column detail
  where needed.
- Tablet: horizontal role navigation; matrix remains horizontally scrollable.
- Mobile: read-first status, score, service and event panels. Wide matrices are
  not scaled down; users scroll/drill into rows.

## Intentionally incomplete

The MVP does not yet render packet/flow telemetry, CPU/memory/network charts,
connection-rate topology edges, browser notifications, sound hooks,
announcements editor, round-extension/service-disable controls, score freeze
controls or a production broadcast graphics overlay. Patch-stage timestamps are
retained in runtime/audit records but are not yet projected as a per-stage
participant timeline. Those require additional authoritative projections; no
random fixture is used in their place.

## Verified screenshots

These captures use the running demo API; they contain no random telemetry:

| Role / viewport | Capture |
|---|---|
| Competitor battle overview · 1920×1080 | [competitor-battle-1920x1080.png](screenshots/competitor-battle-1920x1080.png) |
| Operator command center · 1920×1080 | [operator-command-1920x1080.png](screenshots/operator-command-1920x1080.png) |
| Observer live · 1920×1080 | [observer-live-1920x1080.png](screenshots/observer-live-1920x1080.png) |
| Observer live · 1440×900 | [observer-live-1440x900.png](screenshots/observer-live-1440x900.png) |

`e2e/live-fire.spec.ts` uses an explicitly typed deterministic fixture for
visual regression and permission behavior; production screens use
`httpAttackDefenseApi` and the real SSE adapter. The fixture never ships in the
application bundle.
