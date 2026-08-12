# Broadcast Graphics Overlay

## Purpose and security boundary

The Live Fire dashboard exposes a standalone browser-source route for OBS,
vMix, browser capture and venue displays:

```text
http://localhost:5178/broadcast/overlay?match_id=ad-demo&layout=scorebar&background=transparent
```

This route does not render the normal application shell and never reads or
sends the access token stored by the competitor/operator UI. It polls only:

```text
GET /api/attack-defense/public/matches/{match_id}/broadcast
```

The endpoint is unauthenticated by design and constructs a field whitelist
from the delayed public scoreboard, aggregate service posture and public
tournament projection. It excludes events, team-to-runtime mappings,
endpoints, image references/digests, checker evidence, flags, credentials,
patches, referee reasons and identity subjects. Responses use `no-store`,
`nosniff` and `noindex, nofollow` headers.

The visible **PUBLIC PROJECTION** marker reports the score delay and last
released round. Stealth Mode raises the broadcast delay to the same disclosure
floor used by the public scoreboard. Service health is current but aggregate
only; it never identifies which team owns a degraded instance. Tournament
scores appear only through the already-public finalized fixture result.

## Layouts

| Query | Purpose |
|---|---|
| `layout=scorebar` | Transparent lower-third with match/round clock and ranked score cards |
| `layout=standings` | Full-frame standings plus aggregate service posture |
| `layout=bracket` | Full-frame public LiveCTF elimination bracket |

Shared options:

| Query | Values | Default |
|---|---|---|
| `match_id` | Existing Match ID | `ad-demo` |
| `background` | `transparent`, `solid`, `chroma` | `transparent` |
| `max_teams` | Integer, clamped to 2–16 | `6` |
| `accent` | Six-digit CSS hex color, URL-encoded `#` | `#69afff` |

Examples:

```text
# OBS lower third with alpha
/broadcast/overlay?match_id=ad-demo&layout=scorebar&background=transparent&max_teams=6

# Venue confidence display
/broadcast/overlay?match_id=ad-demo&layout=standings&background=solid

# Green-screen source with tournament bracket
/broadcast/overlay?match_id=fixture-final&layout=bracket&background=chroma&accent=%23f6c85f
```

Unknown layouts/backgrounds and invalid colors fall back to safe defaults;
`max_teams` is bounded. A bracket layout without an attached public tournament
renders an explicit unavailable state instead of fabricated fixtures.

## OBS setup

1. Start the Live Fire Vite server or serve its production build with SPA
   fallback for `/broadcast/*`.
2. Add an OBS **Browser Source**, set the URL to the required overlay and use
   1920×1080 dimensions.
3. Use `background=transparent` for alpha compositing. The document, body and
   application root are explicitly transparent on this route. Use
   `background=chroma` only when the downstream switcher cannot preserve alpha.
4. Keep the browser source network-restricted to the public API/reverse proxy;
   it does not need an operator token or access to management networks.
5. Verify the displayed delay marker before going live. A refresh failure keeps
   the last confirmed snapshot and changes the signal to **FEED STALE**; initial
   failure renders **PUBLIC FEED UNAVAILABLE**.

The API recommends a five-second refresh. The client bounds any server value
to 2–30 seconds and anchors the round countdown to server time. Scores and
posture are never inferred from SSE or animated optimistically.

## Verification

- Python security tests compare the broadcast scoreboard/service payloads to
  their existing public projections and reject sensitive field leakage.
- Playwright loads the overlay while an operator token is present, verifies
  that no privileged shell or fields appear, and captures 1920×1080 standings,
  bracket and RGBA scorebar baselines.
- The transparent scorebar baseline asserts alpha-zero pixels outside the
  graphic by capturing with the browser background omitted.

Current limitations are deliberate: no NDI/SDI output, fill-and-key appliance
integration, sponsor/branding CMS, animated score transitions, rundown control
or multi-Match director console. Those belong outside the public data
projection and can consume this versioned `broadcast-overlay.v1` contract.
