# Optional KOTH Policy

## Scope

KOTH is an opt-in ownership and scoring policy for `attack_defense` and
`hybrid_live_fire`. It is deliberately **not** a fourth Match mode. The legacy
`exercise` engine never creates hills, ownership leases or KOTH scores.

Each enabled team/service instance is one hill. A competitor acquires that
hill by making a valid first submission of an active opponent flag from the
instance. A later valid submission by another team transfers ownership. A new
round flag from the current owner renews the lease. Duplicate and self-flag
submissions never create leases.

This keeps KOTH evidence inside the existing authenticated, rate-limited,
constant-time flag boundary. It does not add an oracle or return victim/service
metadata in the flag-submission response.

## Configuration

KOTH may be changed only while a Match is `draft` or `paused`.

```bash
python3 -m services.attack_defense.cli ad match-pause ad-demo \
  --reason "enable KOTH scoring"

python3 -m services.attack_defense.cli ad koth-configure ad-demo \
  --service-id service-vulnerable-notes \
  --lease-rounds 2 \
  --points-per-round 3 \
  --score-weight 1 \
  --reason "KOTH rules approved for this match"

python3 -m services.attack_defense.cli ad match-resume ad-demo \
  --reason "KOTH policy applied"

python3 -m services.attack_defense.cli ad koth-status ad-demo
```

Omitting `--service-id` selects every enabled GameService. Disable the policy
while the Match is paused:

```bash
python3 -m services.attack_defense.cli ad koth-configure ad-demo --disable \
  --reason "operator disabled KOTH"
```

Environment defaults are `KOTH_DEFAULT_LEASE_ROUNDS=2` and
`KOTH_DEFAULT_POINTS_PER_ROUND=3`. Match configuration and the operator API are
authoritative after creation.

## Lease and scoring rules

- A lease starts in the round in which the valid flag is submitted.
- `lease_rounds=2` includes the acquisition round and the next round.
- The latest valid lease event for a hill is authoritative.
- Reconfiguration starts a new hill activation epoch; old lease history cannot
  silently reactivate.
- At round finalization, the owner earns points only if the victim service
  passed `put_flag`, `get_flag` and `benign_workflow`.
- Points aggregate by owner and GameService into the append-only ledger with
  `score_type=koth`.
- Recalculation derives the same target from round, checks and lease history.
- KOTH weight remains separate from Attack, Flag Defense and Availability.

## API

```http
POST /api/attack-defense/operator/matches/{match_id}/koth/configure
Authorization: Bearer <operator>
Content-Type: application/json

{
  "enabled": true,
  "service_ids": ["service-vulnerable-notes"],
  "lease_rounds": 2,
  "points_per_round": 3,
  "score_weight": 1.0,
  "reason": "approved KOTH rules"
}
```

State views:

- `GET /api/attack-defense/operator/matches/{match_id}/koth`
- `GET /api/attack-defense/matches/{match_id}/koth`

The public view contains target team/service names, current owner, remaining
rounds and point value. It never contains flags, token hashes, source flag IDs,
endpoints, management data, checker evidence or exploit details.

## Persistence, audit and metrics

- `koth_hills` stores configured hills and activation epochs.
- `koth_leases` is append-only and uses a portable monotonic sequence.
- `koth_configuration` and `koth_ownership` are audit/SSE events.
- `attack_defense_koth_ownership_total` counts lease events.
- `attack_defense_koth_hills_enabled` reports enabled hills.

Flag acceptance, Attack ledger insertion and lease acquisition share one
database transaction. PostgreSQL keeps the same idempotency and replica-safety
guarantees as the base flag path.

## MVP limitations

- Ownership proves repeated access to rotating service flags, not an implanted
  agent heartbeat or arbitrary process persistence.
- Hills are symmetric team service instances; a separate shared neutral host
  is not provisioned.
- Points accrue per round rather than continuously per second.
- Checker-system-error compensation follows the existing round policy and
  needs event-specific production review.

## Verification

- SQLite tests cover opt-in mode boundaries, acquisition, transfer, duplicate
  suppression, lease expiry, reconfiguration epoch rotation, functional score
  gating, deterministic recalculation, authorization and public redaction.
- PostgreSQL 17 tests submit the same hill flag concurrently from two replica
  paths and verify one serialized `acquired` event followed by `captured`.
- The full Python repository regression is `341 passed, 6 skipped`; the six
  skipped PostgreSQL-only tests pass in the explicit PostgreSQL profile.
- Live Fire Vitest is `17 passed`, the TypeScript/Vite production build passes,
  and `npm audit` reports 0 vulnerabilities.
