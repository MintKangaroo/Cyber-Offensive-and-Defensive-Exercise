# CYBER RANGE COMMAND SYSTEM

A restrained command interface for exercise controllers and cyber defense teams.
Every visual element should aid operational reading, an operator decision, or
navigation. The working UI is HTML, SVG and live source data; brand media is optional.

## Foundations

Source of truth: `dashboards/shared/src/tokens.css`. Components use semantic custom
properties, never per-page color literals. Navy/graphite surfaces, slate borders and
clear elevation define structure. Cyan means operational/Blue; amber means warning/
Red activity; red means critical; green means recovered; magenta means intelligence;
neutral means unknown. Every badge combines a symbol, text, and a bounded shape.
An unknown asset is not colored healthy.

UI typography uses locally available Pretendard, Inter and system Korean/English
fallbacks. Telemetry uses JetBrains Mono and system monospace fallbacks. No remote
font fetch is required for a disconnected local range. Tokens cover spacing, type,
radii, shadows, density, layers, motion, chart lines, teams, severity and asset state.
`data-contrast="high"` and the operating-system contrast preference are supported.
`data-density` selects compact/comfortable layouts. `prefers-reduced-motion` removes
nonessential transitions. Continuous decorative motion is not part of operations.

## Shared component contract

| Primitive | Purpose / accessibility |
|---|---|
| WorkspaceBar / Icon | Consistent product entry point and code-native icon language |
| Button | Native keyboard interaction; non-submit default prevents accidental commands |
| Panel / MetricCard | Semantic headings; metric source/qualification beside value |
| StatusBadge / SeverityBadge | Symbol + label + shape + semantic color |
| DataTable | Table caption, column headers, focusable horizontal overflow, empty state |
| Timeline | Ordered evidence with timestamp and actor/action detail |
| EmptyState / Skeleton / ErrorState | Explicit absence, loading announcement, error/retry |
| Dialog / Drawer | Native modal focus containment, Escape, accessible name, focus return |
| ErrorBoundary | Recoverable workspace failure instead of a blank page |

The Command application composes these into its sidebar, header, breadcrumb trail,
RBAC navigation, palette, inspector, notifications, event feed, incident cards,
team scores and phase indicators. Promote application-specific components into the
shared package when a second workspace needs the same behavior; do not create
unused wrappers merely to satisfy a component-name checklist.

## Operational layout

Desktop: a persistent navigation rail, slim authenticated context header, status
strip, four high-priority metrics and a map/evidence workspace. Incident management
uses queue → investigation → context. Advanced payloads open on demand. War Room
hides navigation and increases sector prominence; fullscreen is explicitly invoked.

At laptop widths, side context stacks beneath investigations. On mobile, the menu
is a drawer; incident priority and safety state take precedence. Large tables scroll
within their own region rather than expanding the viewport. Test 390px emergency
controls, 768px tablet, 1440px command desk and ultrawide layouts when changing CSS.

## Interaction rules

- Ctrl/Cmd+K opens search. Arrow keys, Tab and Enter navigate; Escape closes.
- Every destructive action names its effect and requires an explicit reason and
  confirmation. Cancel never submits a form.
- Asset colors reflect observed evidence. Sector images contain no state labels.
- Event arrival is batched. Pausing the visible feed does not stop ingestion.
- Replay time is visible and drives all historical panes together.
- AAR metrics identify measurement scope and missing data.
- AI output is marked as a suggestion, never a system state or automatic action.
- No flashing alarms, decorative 3D charts, neon glows or baked-in UI text.

## Verification

Vitest covers transport, stream framing/bounds, source fidelity, role navigation,
replay projections and critical component behavior. Playwright exercises keyboard
navigation, event virtualization, SOC lifecycle, source switching, replay, source
outages, observer restrictions and mobile confirmation. Axe WCAG checks cover login,
overview and incident workbench; automated scans are not a complete WCAG 2.2 AA
conformance audit. Human screen-reader, Korean content, touch and assistive-device
review remain necessary for a formal accessibility claim.

## Brand assets

`HIGGSFIELD_PROMPTS.md` records exact prompts. `asset-manifest.json` maps 19 approved
concepts to filenames, usage, aspect ratios and delivered dimensions.
`asset-provenance.json` records model, generation time and original/delivered hashes.
Hero, eleven sector images, five empty-state illustrations and two short videos
share the same restrained visual direction. WebP is used for image delivery.
Videos load only when requested by a user. Missing assets leave a complete,
operational interface with readable HTML and code-native icons.
