# DEF CON-Inspired Live Fire Design System

The interface is an operations product, not a “hacker movie” skin. Every
accent, animation and chart must correspond to confirmed match data.

## Tokens

Tokens live in `dashboards/livefire/src/index.css`. The palette provides three
surface levels, high-contrast primary/secondary/muted text, separate attack,
defense, availability and operator accents, and status colors. Warning and
critical states are intentionally brighter but not applied to ordinary chrome.

Spacing uses a 4/8px base. Controls use 4px radius, panels 8px. Operational
numbers, clocks, hashes and image digests use tabular monospace; body/navigation
use the system sans stack. Focus rings use a two-pixel information blue.

Status is never color-only:

- healthy: check icon plus `HEALTHY`;
- warning/degraded: triangle plus label;
- critical/failure: exclamation or cross plus label;
- in progress: circular progress glyph plus explicit stage;
- offline: hollow circle plus `OFFLINE`.

## Surfaces and density

- Canvas: page and topology background.
- Surface 1: primary operational panels.
- Surface 2: metrics, cards and controls.
- Surface 3: active selection, selected service and command result.

Cards are not visually identical. Score strips use a compact top edge; service
cards use a left posture edge; events use a category edge; dangerous dialogs
use an operator/critical boundary.

## Motion

Only round urgency, new confirmed events, score/state changes, patch progress,
drawers and dialogs may animate. The current implementation uses a short,
limited countdown/activity pulse and restrained control transitions. Sound is
not enabled by Attack/Defense UI. Existing exercise sound remains explicit
opt-in. `prefers-reduced-motion` reduces all animation and transition durations.

## Shared components

Implemented exports include `LiveMatchHeader`, `RoundCountdown`,
`ConnectionStatus`, `MetricTile`, `ScoreStrip`, `TeamRankBadge`,
`ServiceStatusBadge`, `ServiceMatrix`, `TeamServiceCell`,
`FlagSubmissionPanel`, `SubmissionResultToast`, `PatchPipeline`,
`PatchStatusBadge`, `LiveEventFeed`, `EventSeverityBadge`,
`TacticalTimeline`, `OperatorActionDialog`, `InfrastructureStatusPanel`,
`CheckerResultIndicator`, `LatencySparkline`, `AvailabilityGauge`,
`ScoreDeltaIndicator`, `IncidentQueue`, and `CommandPalette`.

Loading, empty, stale/degraded, unauthorized and error communication use common
state panels. Components do not generate placeholder telemetry.
