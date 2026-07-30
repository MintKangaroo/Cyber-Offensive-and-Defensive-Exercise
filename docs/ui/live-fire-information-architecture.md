# Live Fire Information Architecture

The Vite application preserves the existing CCE exercise interface and selects
one of three explicit Match modes. `exercise` renders the previous dashboard.
`attack_defense` and `hybrid_live_fire` render the operations shell.

Menus are generated from authenticated role, not a visual role switch:

- Competitor: Battle Overview, Attack Console, Defense Console, Services,
  Patches, Scoreboard, Event Feed, Team Settings.
- Operator: Command Center, Match Control, Team Matrix, Service Matrix, Round
  Control, Flag Operations, Checker Operations, Patch Review, Scoring,
  Evidence, Infrastructure, Observability.
- Observer: Live Overview, Scoreboard, Match Timeline, Service Status, Major
  Events.

Unauthorized menu items are absent. Back-end authorization remains the security
boundary.

## Three-second scan hierarchy

1. Sticky Live Match Header: mode, match state/name, round, countdown, server
   clock, feed health, team and urgent count.
2. Tactical score/global status strip.
3. Own-service or team×service posture.
4. Live event/incident stream.
5. Drill-down detail and action panels.

Competitors see only their service internals and the minimum public attack
surface. Operators see the full instance matrix and evidence-backed control
state. Observers receive scoreboard, sanitized availability summaries, major
events and timeline only.

## Routes and presentation

The SPA supports query-selected modes and observer-safe presentation paths:

- `/?mode=exercise`
- `/?mode=attack_defense`
- `/?mode=hybrid_live_fire`
- `/observer/live`
- `/observer/scoreboard`
- `/observer/timeline`

The server must use SPA fallback for these routes. Observer path forces observer
UX even when a more privileged token exists, preventing accidental broadcast
of operator panels.
