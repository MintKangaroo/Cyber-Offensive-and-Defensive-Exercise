# Optional Stealth Mode Policy

Stealth Mode is an opt-in disclosure and scoring policy for
`attack_defense` and `hybrid_live_fire`. It is not a fourth Match mode. The
legacy `exercise` engine never creates Stealth incidents or scores.

The policy does not change flag syntax, validation, submission responses,
Attack points, active windows, KOTH capture, or checker behavior. A first valid
opponent flag submission additionally creates an internal incident. Operators
see it immediately; competitors and observers do not.

## Disclosure and detection flow

```text
valid opponent flag submission
  -> normal Attack result and ledger entry
  -> internal attacker/victim/service incident
  -> defender may submit independent SIEM/EDR evidence hash
  -> detection window closes
  -> detected: Stealth Detection points to victim
     undetected: Stealth Attack points to attacker
  -> delayed, attacker-redacted alert becomes visible
```

The default alert delay and detection window are both two rounds. A report must
arrive no later than the detection deadline. Because the alert is not released
until after that deadline, it cannot be used to manufacture a matching report.

The report response is always:

```json
{
  "recorded": true,
  "status": "pending_verification",
  "report_id": "opaque-id"
}
```

It never reveals whether an incident was matched. A lowercase SHA-256 indicator
and a short safe summary are stored; raw telemetry, credentials, packets and
flags must remain in the team's evidence system.

## Configuration

Pause a running Match before changing the policy:

```bash
python3 -m services.attack_defense.cli ad match-pause ad-demo \
  --reason "enable delayed attack disclosure"

python3 -m services.attack_defense.cli ad stealth-configure ad-demo \
  --alert-delay-rounds 2 \
  --detection-window-rounds 2 \
  --attacker-points 2 \
  --defender-points 2 \
  --attack-score-weight 1 \
  --detection-score-weight 1 \
  --reason "approved Stealth rules"

python3 -m services.attack_defense.cli ad match-resume ad-demo \
  --reason "Stealth policy applied"

python3 -m services.attack_defense.cli ad stealth-status ad-demo
```

Disabling or re-enabling rotates the policy activation epoch. Old incident
history remains operator evidence but cannot silently reappear or score under
the new policy.

## Defender evidence submission

Hash a stable indicator or local evidence bundle, then submit only the hash and
safe summary. Reuse the same idempotency key when retrying the same report.

```bash
export ATTACK_DEFENSE_COMPETITOR_TOKEN='<team access token>'
python3 -m services.attack_defense.cli ad stealth-detection-report \
  ad-demo service-vulnerable-notes \
  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  "SIEM and EDR correlation for anomalous note access" \
  --idempotency-key team01-round42-notes-01
```

Reports are rate-limited by a shared database counter. Submitting reports for
every service and round is not a reliable oracle and receives no matching
result. The MVP intentionally applies no automatic false-positive penalty;
operators can review report quality and use an audited adjustment if required.

## Score and public projection

- `stealth_attack`: awarded to the attacker when the detection deadline closes
  without a matched report.
- `stealth_detection`: awarded to the victim when a report matched before the
  deadline.
- Both are independent append-only ledger categories with separate weights.
- Deterministic round snapshots make recalculation idempotent.
- Public scoreboard delay is at least the configured Stealth alert delay.
- Public KOTH ownership uses the same as-of round while Stealth is active.
- Immediate KOTH ownership SSE events and internal incident events are
  suppressed for non-operators; delayed state endpoints are authoritative.

Participant alerts expose only own victim service, occurred round and final
detected/undetected outcome. They do not expose attacker identity, submission
ID, flag, endpoint, checker evidence or report matching internals. Observer
output is delayed and aggregated by service without team attribution.

## API

- `POST /api/attack-defense/operator/matches/{match_id}/stealth/configure`
- `GET /api/attack-defense/operator/matches/{match_id}/stealth`
- `POST /api/attack-defense/matches/{match_id}/stealth/detections`
- `GET /api/attack-defense/matches/{match_id}/stealth`
- `GET /api/attack-defense/public/matches/{match_id}/stealth/summary`

Detection submission requires authentication, Match membership,
`Idempotency-Key`, policy activation, an active round and rate-limit capacity.

## Persistence, audit and metrics

- `stealth_incidents`: internal accepted-attack timeline and frozen scoring
  policy values.
- `stealth_detection_reports`: append-only hashed defender reports and internal
  match result.
- Audit events: `stealth_configuration`, `stealth_incident`, and
  `stealth_detection_report`.
- Metrics: `attack_defense_stealth_incident_total`,
  `attack_defense_stealth_detection_report_total`, and
  `attack_defense_stealth_detected_total`.

## MVP limitations

- A report matches one oldest eligible incident for the defended service; it
  does not perform semantic SIEM rule evaluation.
- The server verifies timing and scope, not the authenticity of the external
  evidence represented by the hash.
- Raw evidence retention, signature, chain of custody and operator adjudication
  remain external responsibilities.
- An event ending before a future detection deadline requires an operator
  policy decision; the MVP does not synthesize missing future rounds.
- Sophisticated traffic attribution, stealth implant proof and exploit-family
  classification are outside this policy.

## Verification

- SQLite tests cover mode boundaries, unchanged flag responses, delayed
  release, attacker redaction, report idempotency, no-oracle responses,
  detected/undetected score decisions, recalculation and KOTH delay alignment.
- PostgreSQL 17 tests submit two detection reports through separate component
  instances and verify that exactly one locks and matches the incident.
- Full Python regression: `341 passed, 6 skipped`; all six PostgreSQL-only tests
  pass in the explicit PostgreSQL profile.
- Live Fire Vitest: `17 passed`; TypeScript/Vite production build passes and
  `npm audit` reports 0 vulnerabilities.
