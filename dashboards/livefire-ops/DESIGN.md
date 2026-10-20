---
name: Live-Fire Ops Console
description: CCE-broadcast national live-fire operations console — radial domestatus arena drilling into per-facility operator consoles.
colors:
  space: "#050a15"
  bg: "#091120"
  panel: "#0d1a2c"
  panel2: "#0f1f34"
  raised: "#13243b"
  line: "#21374f"
  line2: "#2e496a"
  tick: "#4fb3e6"
  txt: "#e9f0f9"
  mut: "#8aa3c2"
  sub: "#5f7b9e"
  dim: "#45607e"
  red: "#ff5b60"
  red2: "#e23b43"
  redbg: "#1c0f15"
  cyan: "#54b8ec"
  blue: "#3f7fd6"
  purple: "#9a7ae6"
  orange: "#ff7a44"
  green: "#49c88a"
  amber: "#f2b84b"
typography:
  display:
    fontFamily: "Saira Condensed, Noto Sans KR, system-ui, sans-serif"
    fontSize: "17px"
    fontWeight: 800
    lineHeight: 1
    letterSpacing: "0.02em"
  heading-ko:
    fontFamily: "Noto Sans KR, Saira Condensed, system-ui, sans-serif"
    fontSize: "15px"
    fontWeight: 800
    lineHeight: 1.1
    letterSpacing: "normal"
  data:
    fontFamily: "JetBrains Mono, Noto Sans KR, ui-monospace, monospace"
    fontSize: "24px"
    fontWeight: 700
    lineHeight: 1
    letterSpacing: "0.06em"
  body:
    fontFamily: "Noto Sans KR, Saira Condensed, system-ui, sans-serif"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.4
    letterSpacing: "normal"
  label:
    fontFamily: "JetBrains Mono, Noto Sans KR, ui-monospace, monospace"
    fontSize: "8px"
    fontWeight: 400
    lineHeight: 1.2
    letterSpacing: "0.16em"
rounded:
  none: "0"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "18px"
  xl: "22px"
components:
  button-primary:
    backgroundColor: "{colors.red2}"
    textColor: "#ffffff"
    typography: "{typography.display}"
    rounded: "{rounded.none}"
    padding: "9px 18px"
  button-primary-hover:
    backgroundColor: "{colors.red}"
    textColor: "#ffffff"
  button-primary-disabled:
    backgroundColor: "{colors.red2}"
    textColor: "#ffffff"
  button-ghost:
    backgroundColor: "transparent"
    textColor: "{colors.mut}"
    typography: "{typography.label}"
    rounded: "{rounded.none}"
    padding: "0 16px"
  button-ghost-hover:
    backgroundColor: "transparent"
    textColor: "{colors.cyan}"
  panel:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.txt}"
    rounded: "{rounded.none}"
  panel-header:
    backgroundColor: "{colors.panel2}"
    textColor: "{colors.sub}"
    typography: "{typography.label}"
    padding: "8px 12px"
  enum-up:
    backgroundColor: "#0d2a1e"
    textColor: "{colors.green}"
    typography: "{typography.label}"
    padding: "1px 5px"
  enum-compromised:
    backgroundColor: "#2a1013"
    textColor: "{colors.red}"
    typography: "{typography.label}"
    padding: "1px 5px"
  enum-down:
    backgroundColor: "#2a2410"
    textColor: "{colors.amber}"
    typography: "{typography.label}"
    padding: "1px 5px"
---

# Design System: Live-Fire Ops Console

## Overview

**Creative North Star: "The Broadcast War Room"**

This is a national live-fire cyber-range operations console built to be read like a televised CCE / Locked Shields broadcast board, not a CTF flag-submission form. It opens on a radial "dome" status arena — the whole country's critical-infrastructure under live fire, rendered as a constellation of facility nodes fanning up from a single apex — and drills down into a flat, dense, per-facility operator console (OT intrusion map, physical-twin schematic, live register table, service-status board, kill-chain chevrons). Everything on screen is grounded in real twin code: asset names, protocols, ports, registers, vulnerability IDs and scores are quoted, never invented.

The world sits on the platform's shared dark tokens but overlays its own CCE-broadcast language: a deep navy space field (#050a15 / #091120), a strict **red↔blue duality** (red = attack / Red-team / live danger; cyan and blue = defense / systems / telemetry), hairline-bordered flat panels, bracket-HUD corner ticks, and operator-display typography. The density is high and deliberate: this is a war-room surface meant to be scanned under low light by an operator mid-engagement, so legibility and status-at-a-glance win over whitespace.

Explicitly rejected: CTF flag-submission UI; the generic SOC panel-grid skin; and the AI-neon cyberpunk glow skin. The finished build removed the bottom radial bloom/vignette that an earlier pass carried — surfaces are flat, lit only by tonal layering and hairline borders.

**Key Characteristics:**
- Deep-navy broadcast space with a radial dome-and-constellation signature.
- Red↔blue duality as the core semantic axis; status is color, fill, ring-thickness, never glow.
- Flat hairline panels with bracket-HUD corner ticks; zero corner radius.
- Tri-font HUD stack: Saira Condensed (latin display), Noto Sans KR (korean headings), JetBrains Mono (all data).
- Drawn single-stroke SVG icons only; no emoji, no icon fonts.

## Colors

A cold deep-navy ground with a two-pole accent system — red for the attacker and the live threat, cyan/blue for defense and telemetry — plus a tight set of node-state hues.

### Primary
- **Live Red** (`{colors.red}` #ff5b60): the attacker and the live-danger pole. Active target node, "LIVE" indicators, me-row in scoreboard, compromised registers, objective-phase chevron, primary action button. The loudest voice on the board.
- **Action Red** (`{colors.red2}` #e23b43): the solid fill under the execute button and owned/target node tags — a slightly deeper red reserved for filled surfaces so #ff5b60 stays the signal color.
- **Threat Red Wash** (`{colors.redbg}` #1c0f15): near-black red tint behind the objective bar, selected attack rows, and the "on" sector row — a danger ground, not a border.

### Secondary
- **HUD Cyan** (`{colors.cyan}` #54b8ec): the defense/telemetry pole. TIME-REMAINING timer, focus rings, defended-node fill, dome rim ticks and sweep, scoreboard scores, hover affordance on back controls.
- **Tick Cyan** (`{colors.tick}` #4fb3e6): the bracket-HUD corner ticks on every console panel and the drill-down breadcrumb bracket.
- **System Blue** (`{colors.blue}` #3f7fd6): done kill-chain phases, defense solve-log tags, nominal register values — the calmer defense tone where cyan would be too hot.

### Tertiary
- **Strike Orange** (`{colors.orange}` #ff7a44): the default "engaged / under attack" arena node square.
- **Patched Green** (`{colors.green}` #49c88a): patched node, service "up" enum.
- **Alert Amber** (`{colors.amber}` #f2b84b): patch-count LED, degraded/"down" service, high-but-not-critical register values.
- **Signal Purple** (`{colors.purple}` #9a7ae6): a single low-opacity dome radar-fan sector; not used on content.

### Neutral
- **Deep Space** (`{colors.space}` #050a15): the root body background, darkest layer.
- **Base Navy** (`{colors.bg}` #091120): app/console gradient base.
- **Panel / Panel-2 / Raised** (`{colors.panel}` #0d1a2c / `{colors.panel2}` #0f1f34 / `{colors.raised}` #13243b): the tonal elevation ladder — content panels, panel headers, raised chrome.
- **Line / Line-2** (`{colors.line}` #21374f / `{colors.line2}` #2e496a): hairline borders and dividers; line-2 is the heavier structural divider between major regions.
- **Primary / Muted / Sub / Dim text** (`{colors.txt}` #e9f0f9 / `{colors.mut}` #8aa3c2 / `{colors.sub}` #5f7b9e / `{colors.dim}` #45607e): the four-step cool-navy text ramp, from headings down to resting icon strokes and inactive chevron numbers.

### Named Rules
**The Red↔Blue Duality Rule.** Red always means attacker / live danger; cyan and blue always mean defense / system / telemetry. Never color a defensive readout red or an attack readout blue — the two poles carry the whole broadcast's meaning.

**The Status-Is-Not-Glow Rule.** Node and register status is expressed through fill color, ring thickness, and label color only. The single `box-shadow` on the active node is a zero-blur solid ring (`0 0 0 5px`), not a halo. No bloom, no glow, no vignette.

## Typography

**Display Font:** Saira Condensed (self-hosted woff2, weights 500/600/700), with Noto Sans KR fallback
**Body / Heading Font:** Noto Sans KR (CDN, weights 400/500/700/900)
**Data / Mono Font:** JetBrains Mono (self-hosted woff2, weights 400/500/700)

**Character:** A tri-font HUD stack. Saira Condensed carries uppercase latin operation display (`.lf-op`, +0.02em, uppercase); Noto Sans KR carries korean facility names and headings at heavy weights; JetBrains Mono carries every number, code, timer, label and telemetry string. The pairing reads as a live broadcast telemetry overlay.

### Hierarchy
- **Display** (Saira Condensed 800, 16–17px, +0.02em, uppercase): topbar brand line and facility console title (`.t2`, `.title .l2`).
- **Heading (Korean)** (Noto Sans KR 800, 15px): facility names (`.facname`) and node/section names.
- **Data** (JetBrains Mono 700, 19–24px, +0.06em): timer-trio values, patch-count LED, console stat values — the big glanceable numbers.
- **Body** (Noto Sans KR 400, 13px, 1.4): base UI text, team names, log prose.
- **Label** (JetBrains Mono, 8–10px, +0.12em to +0.24em, uppercase, in `{colors.sub}`): every field key, overlay header, enum badge, and column header — the pervasive HUD micro-label.

### Named Rules
**The Mono-For-Truth Rule.** Any value quoted from the twin — register, port, protocol, score, timer, vuln ID, timestamp — is set in JetBrains Mono. Prose and names are sans; data is mono. The mono face is the signal that this is real telemetry, not copy.

## Layout

Two full-viewport scopes, each `100vh` and overflow-hidden on desktop.

**Arena** (`.lf-arena`): absolutely-positioned broadcast board — a 52px topbar, a 42px bottom active-strike ticker, and between them an absolute stage holding the radial dome SVG and percent-positioned facility nodes. HUD overlays float at fixed anchors: timer-trio top-left (210px), scoreboard bottom-left (230px), solve-log right (300px).

**Console** (`.lf-console`): a vertical flex stack — top title/stat bar, kill-chain chevron row, then a three-column CSS grid `236px minmax(0,1fr) 452px` (scoreboard+sectors / OT map / facility twin), gap 8px, padding 8px, then an exploit bar and foot ticker.

**Spacing rhythm:** an 8px base gap governs the grid and column stacks; internal padding steps through 6/8/9/12/14/18/22px. Panel headers sit at 8px 12px.

**Responsive:** at ≤1024px both scopes drop their fixed viewport (`height:auto`, body scrolls), the console grid collapses to a single column, the OT map becomes a 56vh block, stat cells wrap to thirds, and kill-chain chevrons scroll horizontally; the arena stage becomes a relative 74vw block with panels stacked full-width. At ≤560px stat cells go to halves and arena node labels shrink and drop their secondary ID. `prefers-reduced-motion` kills all animation and transition.

## Elevation & Depth

Flat by doctrine. There are no ambient or cast shadows anywhere in the system; depth comes entirely from a tonal navy ladder (space → bg → panel → panel2 → raised) plus 1px hairline borders in line/line-2. Panels read as lit by their border and their fill step, not by a shadow. The one `box-shadow` present is a zero-blur solid ring on the active arena node (a HUD accent, not elevation).

### Named Rules
**The Flat-Panel Rule.** Surfaces never lift. Elevation is one tonal step up plus a hairline border; if a surface needs to feel active it changes its border color or fill ground, never its shadow.

## Shapes

Hard-edged throughout: zero border-radius on every panel, button, node, badge and input surface (`{rounded.none}`). The form language is the rectangle and the hairline. Three signature silhouettes break the grid: the **bracket-HUD corner tick** (9px L-shaped `::before`/`::after` in tick-cyan on console panels), the **kill-chain chevron** (phase cells clipped with `polygon(14px 0, 100% 0, 100% 100%, 14px 100%, 0 50%)` to point rightward), and the **hexagon brand mark** (`polygon(50% 0, 100% 25%, 100% 75%, 50% 100%, 0 75%, 0 25%)` split diagonally red/blue). Icons are single-stroke SVG on a 24×24 box, strokeWidth 1.6, `currentColor`.

## Components

### Buttons
- **Shape:** sharp rectangle (0 radius).
- **Primary (Execute):** Action Red fill (`{colors.red2}`) with a `#ff7a7e` 1px border, white Saira uppercase display at 12px/+0.08em, padding 9px 18px.
- **Hover / Disabled:** hover brightens fill to Live Red (`{colors.red}`); disabled drops to 0.6 opacity, default cursor.
- **Ghost (Back / breadcrumb):** borderless, mono label in muted text, hover shifts text to HUD cyan. No fill, no underline.

### Chips / Badges
- **Enum status badge** (`.en`, `.tag`, `.cp`): tiny mono 8px uppercase tag, 1px 5px padding, colored pair per state — up = green on #0d2a1e, compromised = red on #2a1013, down = amber on #2a2410. Credential/patch chips (`.cp`) are hollow: 1px border in line-2 with amber or blue text.
- **Solve/strike tags** (`.atk` / `.def`): attack = #ff9a9e on #2a1013, defense = #86cef0 on #0c2636 — the duality in badge form.

### Cards / Containers (Panel)
- **Corner Style:** 0 radius; console panels carry the bracket-HUD corner ticks.
- **Background:** `{colors.panel}` with a `{colors.panel2}` header band.
- **Shadow Strategy:** none — see Elevation.
- **Border:** 1px `{colors.line}`; major region seams use `{colors.line2}`.
- **Internal Padding:** header 8px 12px; body 10px 12px.

### Focus / Selection (browser surfaces)
- **Focus:** `:focus-visible` → 2px solid HUD cyan outline, 1px offset. Part of the design, not a reset.
- **Selection:** `::selection` → red tint `#ff5b6055` on white text.
- **Scrollbar:** 9px, thumb `#22394f` radius 6px (the sole rounded value in the system), transparent track, scoped to `.lf-root`.

### Signature: Dome Arena + Facility Constellation
A radial SVG dome (apex at bottom-center) with concentric arcs, radial grid lines, a dashed cyan rim, a radar sweep, and three low-opacity fan sectors (white/blue/purple). Facility nodes are percent-positioned buttons: an 11px status square (orange engaged / cyan defended / green patched / red active) over a mono label; the active target grows to a 15px red square inside two concentric solid rings.

### Signature: Facility Operator Console
Per-facility drill-down: an OT intrusion map on a 34px dotted grid with owned/target nodes and an active lateral-movement edge; a physical-twin schematic (power one-line / hospital vitals / water process / generic); a live register table (name · addr · value · state, value toned red/amber/blue/neutral); a two-column service-status enum board; a kill-chain chevron strip; and a stat bar carrying the timer trio and scores.

## Do's and Don'ts

### Do:
- **Do** keep the red↔blue duality absolute: red = attack/live, cyan+blue = defense/system.
- **Do** set every twin-sourced value (register, port, score, timer, vuln ID) in JetBrains Mono.
- **Do** express status through fill, ring thickness, and label color; keep panels flat with a hairline border and one tonal step.
- **Do** use the bracket-HUD corner tick, kill-chain chevron, and hexagon brand as the only non-rectangular silhouettes.
- **Do** draw icons as single-stroke 24×24 SVG with `currentColor`.

### Don't:
- **Don't** add glow, bloom, vignette, grain, or scanlines — the finish removed the radial bloom on purpose.
- **Don't** round corners; the only radius in the system is the 6px scrollbar thumb.
- **Don't** use emoji or icon fonts for iconography.
- **Don't** ship a CTF flag-submission panel, a generic SOC panel-grid, or neon cyberpunk treatment.
- **Don't** reach for a system display face; latin display is Saira Condensed, korean is Noto Sans KR, data is JetBrains Mono.
