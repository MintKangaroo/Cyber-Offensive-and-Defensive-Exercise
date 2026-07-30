# Attack/Defense API

Base URL: `http://localhost:8100`.

Authentication uses existing HS256 access JWTs. Competitor identity is taken
only from signed `team_id` and `match_id` claims, never from request bodies.
`red` and `blue` remain accepted as competitor aliases for compatibility.
`instructor` and `operator` can use operator routes.

## Match and operator routes

| Method | Path | Role |
|---|---|---|
| POST | `/api/attack-defense/matches` | operator |
| POST | `/api/attack-defense/matches/{id}/teams` | operator |
| POST | `/api/attack-defense/matches/{id}/services` | operator |
| POST | `/api/attack-defense/matches/{id}/start|pause|resume|end` | operator |
| GET | `/api/attack-defense/matches/{id}/rounds/current` | operator |
| POST | `/api/attack-defense/matches/{id}/rounds/current/finalize|extend|tick` | operator |
| GET | `/api/attack-defense/operator/matches/{id}/services|checks|flags|patches|audit|scoreboard` | operator |
| POST | `/api/attack-defense/operator/matches/{id}/teams/{team}/services/{service}/restart|rollback` | operator |
| POST | `/api/attack-defense/matches/{id}/score/adjust|recalculate` | operator |
| POST | `/api/attack-defense/internal/matches/{id}/score-events` | operator/service integration |
| POST | `/api/attack-defense/operator/runtime/jobs/claim` | trusted operator runner |
| POST | `/api/attack-defense/operator/runtime/jobs/{job}/complete` | trusted operator runner |

The hybrid score event endpoint requires a caller-supplied unique `event_id` and
rejects categories disabled in Match configuration.

## Participant and public routes

| Method | Path | Exposure |
|---|---|---|
| GET | `/api/attack-defense/matches/{id}/state` | own membership |
| GET | `/api/attack-defense/matches/{id}/services/me` | own instances only |
| GET | `/api/attack-defense/matches/{id}/availability/me` | own summary only |
| GET | `/api/attack-defense/matches/{id}/attack-surface` | opponent names/services, no internal status |
| POST | `/api/attack-defense/matches/{id}/flags/submit` | competitor |
| POST | `/api/attack-defense/matches/{id}/services/{service}/patches` | competitor |
| GET | `/api/attack-defense/matches/{id}/patches[/{patch}]` | own patches only |
| GET | `/api/attack-defense/matches/{id}/scoreboard` | sanitized public/delayed |
| GET | `/api/attack-defense/public/matches/{id}/state` | public |
| GET | `/api/attack-defense/public/matches/{id}/service-summary` | aggregate healthy/total only |
| GET | `/api/attack-defense/matches/{id}/events/stream` | role-filtered SSE |

Flag submission:

```http
POST /api/attack-defense/matches/ad-demo/flags/submit
Authorization: Bearer <competitor access token>
Content-Type: application/json

{"flag":"FLAG{opaque-token}"}
```

Accepted:

```json
{"accepted":true,"status":"accepted","score_delta":10}
```

Every rejection exposed to a competitor is generalized:

```json
{"accepted":false,"status":"rejected","reason":"invalid_or_inactive"}
```

Victim, service, exact expiry, duplicate state, and internal reason remain in
operator-only audit evidence.

## Scoreboard

Public output includes delay, last public round, provisional state and raw score
categories. Operator output has no configured delay. Hybrid categories are
separate columns; weighted `total` is calculated from Match configuration.
