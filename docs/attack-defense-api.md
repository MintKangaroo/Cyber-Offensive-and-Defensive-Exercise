# Attack/Defense API

Default base URL: `http://localhost:8100`. The local HA profile uses
`http://localhost:8110` through HAProxy.

`GET /health` is liveness. `GET /ready` checks database access and
application/database clock skew; the HA load balancer sends traffic only to
ready replicas.

Authentication uses existing HS256 access JWTs. Competitor identity is taken
only from signed `team_id` and `match_id` claims, never from request bodies.
`red` and `blue` remain accepted as competitor aliases for compatibility.
`instructor` and `operator` can use operator routes.

Tournament participants may additionally receive a signed `tournament_id`
claim. It authorizes only their bracket projection. Fixture mutations still
require fresh Match-local `match_id` and `team_id` claims.

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
| GET | `/api/attack-defense/operator/ha/status` | operator |
| POST | `/api/attack-defense/operator/matches/{id}/instances/{instance}/runtime-result` | trusted operator reconciler |
| POST | `/api/attack-defense/operator/matches/{id}/captures` | operator, binary classic PCAP + reason |
| GET | `/api/attack-defense/operator/matches/{id}/captures` | operator privacy metadata |
| POST | `/api/attack-defense/operator/matches/{id}/koth/configure` | operator, draft/paused only, reason required |
| GET | `/api/attack-defense/operator/matches/{id}/koth` | operator real-time ownership and policy |
| POST | `/api/attack-defense/operator/matches/{id}/stealth/configure` | operator, draft/paused only, reason required |
| GET | `/api/attack-defense/operator/matches/{id}/stealth` | operator real-time incidents and internal report results |
| POST | `/api/attack-defense/operator/tournaments` | operator creates a 2/4/8/16-entry single-elimination tournament |
| GET | `/api/attack-defense/operator/tournaments[/{id}]` | operator list/detail including identity and fixture Match mapping |
| POST | `/api/attack-defense/operator/tournaments/{id}/entries|services` | operator draft registration |
| POST | `/api/attack-defense/operator/tournaments/{id}/seed|start|reconcile` | operator lifecycle, reason required |
| POST | `/api/attack-defense/operator/tournaments/{id}/fixtures/{fixture}/start|finalize` | operator fixture lifecycle, reason required |

The hybrid score event endpoint requires a caller-supplied unique `event_id` and
rejects categories disabled in Match configuration.

`ha/status` exposes only backend type, HA capability, database time, bounded
clock skew, migration versions, running Match count and the current engine
owner ID. It never exposes the DSN or database credentials.

Runtime job completion requires the opaque `claim_token` returned inside the
claimed job's result. Reclaiming a stale job rotates the token, so an older
worker receives `409` if it attempts completion.

The runtime-result endpoint records a Compose/Kubernetes reconciliation result
and writes audit evidence. It accepts only bounded HTTP endpoints with explicit
ports; Kubernetes mode additionally requires cluster `.svc` DNS. A reason is
mandatory. Example:

```json
{
  "success": true,
  "runtime_id": "vulnerable-notes-47d91b20",
  "endpoint": "http://vulnerable-notes-47d91b20.ad-match-team.svc:9000",
  "management_endpoint": "http://vulnerable-notes-47d91b20.ad-match-team.svc:9001",
  "image_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "error_code": null,
  "reason": "initial tournament service deployment"
}
```

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
| GET | `/api/attack-defense/public/matches/{id}/broadcast` | versioned no-store public graphics snapshot; delayed scores, aggregate services, optional public bracket; no events or sensitive fields |
| GET | `/api/attack-defense/matches/{id}/events/stream` | role-filtered SSE |
| GET | `/api/attack-defense/matches/{id}/captures` | Match competitors, delayed metadata |
| GET | `/api/attack-defense/matches/{id}/captures/{capture}/download` | Match competitors, delayed/watermarked PCAP |
| GET | `/api/attack-defense/matches/{id}/koth` | Match competitors, sanitized current ownership |
| POST | `/api/attack-defense/matches/{id}/stealth/detections` | competitor, own membership, idempotency key and rate limit |
| GET | `/api/attack-defense/matches/{id}/stealth` | competitor, own delayed attacker-redacted alerts |
| GET | `/api/attack-defense/public/matches/{id}/stealth/summary` | delayed service aggregate, no team attribution |
| GET | `/api/attack-defense/tournaments/{id}` | registered tournament participant projection |
| GET | `/api/attack-defense/public/tournaments/{id}` | public bracket, no credential/runtime/identity mapping |

Tournament creation example:

```json
{
  "id": "livectf-2026",
  "name": "LiveCTF 2026",
  "bracket_size": 8,
  "match_mode": "attack_defense",
  "round_duration_seconds": 120,
  "active_flag_window": 3,
  "match_config": {"scoreboard_delay_rounds": 0}
}
```

Fixture finalization normally derives the winner from the finalized operator
scoreboard. `winner_entry_id` is optional and accepted only for one of the two
fixture participants; use it for a documented tie-break. See
[LiveCTF Tournament Orchestration](attack-defense-tournament.md).

The broadcast endpoint intentionally accepts no access token. Its
`broadcast-overlay.v1` response is a whitelist composition of the existing
public projections and includes a `disclosure` object with score delay, last
public round, aggregate-only service policy and explicit false values for
events/sensitive fields. See [Broadcast Graphics Overlay](attack-defense-broadcast.md).

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

An accepted submission can also acquire, capture or renew an enabled KOTH hill.
The flag response deliberately remains unchanged, so it cannot reveal whether a
specific token affected KOTH ownership.

## Sanitized captures

Operator ingest uses `application/vnd.tcpdump.pcap` or
`application/octet-stream`. The binary body is bounded by `PCAP_MAX_UPLOAD_MB`;
an `X-Operation-Reason` header is mandatory. Optional `X-Round-Id` and
`X-Service-Id` values are ownership-checked against the Match.

```http
POST /api/attack-defense/operator/matches/ad-demo/captures
Authorization: Bearer <operator token>
Content-Type: application/vnd.tcpdump.pcap
X-Operation-Reason: round 42 post-round evidence

<classic PCAP bytes>
```

Raw capture bytes are discarded after in-memory sanitization. Competitor
downloads return HTTP `425` with `Retry-After` before release. Successful
downloads include `X-Capture-SHA256`, `X-Capture-Watermark`, `Cache-Control:
private, no-store`, and a safe attachment filename. See
[PCAP Privacy and Delayed Delivery](attack-defense-pcap.md).

## Scoreboard

Public output includes delay, last public round, provisional state and raw score
categories. Operator output has no configured delay. Hybrid categories are
separate columns; weighted `total` is calculated from Match configuration.
When enabled, `koth` remains its own ledger and scoreboard category and uses its
independent configured weight.

Stealth adds independent `stealth_attack` and `stealth_detection` categories.
Its alert delay becomes the minimum public scoreboard delay and the public KOTH
as-of delay. Operator score remains real-time.

## Stealth detection report

```http
POST /api/attack-defense/matches/ad-demo/stealth/detections
Authorization: Bearer <competitor access token>
Idempotency-Key: team01-round42-notes-01
Content-Type: application/json

{
  "service_id": "service-vulnerable-notes",
  "indicator_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "evidence_summary": "SIEM and EDR correlation for anomalous note access"
}
```

Every successfully recorded report returns the same generalized state:

```json
{"recorded":true,"status":"pending_verification","report_id":"opaque-id"}
```

The response does not reveal whether a matching incident exists. Raw evidence
must not be sent to this endpoint. See
[Stealth Mode Policy](attack-defense-stealth.md).
