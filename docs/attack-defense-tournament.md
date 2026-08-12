# LiveCTF Tournament Orchestration

## Boundary

LiveCTF is a parent orchestration layer, not a fourth Match mode. Every fixture
is an ordinary, isolated `attack_defense` or `hybrid_live_fire` Match and uses
the existing round engine, flags, checker, patch pipeline, ledger, audit and
score visibility policy. The existing `exercise` mode is never enrolled in a
tournament and remains controlled by the legacy scenario/inject services.

The MVP supports deterministic single elimination with exactly 2, 4, 8 or 16
entries. Byes, pools, Swiss pairing, double elimination and LiveCTF head-to-head
challenge brackets are intentionally deferred.

## Identity and isolation

A `tournament_entry` is the stable team identity across the bracket. A fixture
materializes fresh Match-local `teams`, `game_services` and
`team_service_instances`; `tournament_match_teams` is the operator-only map
between those scopes. This prevents a flag, patch, score event or Match token
from one fixture being valid in the next fixture.

Tournament access tokens may carry a signed `tournament_id` claim. That claim
can read the participant's bracket projection, but it cannot call a fixture's
flag, service or patch APIs. Those operations still require a newly issued
`match_id` + Match-local `team_id` token. Public bracket output removes identity
subjects, Match IDs, loser IDs, operator reasons, credentials and runtime data.

## Deterministic lifecycle

```text
draft -> seeded -> running -> completed
             |          |
             |          +-- fixture scheduled -> running -> finalized
             +-- all first-stage fixtures materialized as ordinary Matches
```

Standard seed placement is used (`1×8`, `4×5`, `2×7`, `3×6` for eight teams).
Seeding creates every stage and fixture with stable IDs. `reconcile` safely
materializes any fixture whose two entries are known and can be repeated after
a process restart. Finalization reads the fixture's authoritative operator
scoreboard and orders teams by weighted total, then Attack, then Availability.
An exact tie is never silently broken: a referee must provide the winning entry
and an audit reason. The winner is atomically propagated to the next fixture.

## Operator quick start

Set `INSTRUCTOR_TOKEN` and create the tournament:

```bash
python3 -m services.attack_defense.cli ad tournament-create \
  --id livectf-2026 --name "LiveCTF 2026" --bracket-size 4 \
  --match-mode attack_defense

for n in 1 2 3 4; do
  python3 -m services.attack_defense.cli ad tournament-entry-add livectf-2026 \
    --id "entry-${n}" --slug "team-0${n}" --name "Team ${n}" \
    --identity-subject "team0${n}" --seed "${n}"
done

python3 -m services.attack_defense.cli ad tournament-service-add livectf-2026 \
  --id tournament-notes --slug vulnerable-notes --name "Vulnerable Notes" \
  --base-image registry.local:5000/base/vulnerable-notes:v1 \
  --internal-port 9000 --checker-type vulnerable_notes \
  --config '{"endpoint_template":"http://{team_slug}-{service_slug}:9000","management_endpoint_template":"http://{team_slug}-{service_slug}:9001"}'

python3 -m services.attack_defense.cli ad tournament-seed livectf-2026 \
  --reason "approved tournament seeding"
python3 -m services.attack_defense.cli ad tournament-start livectf-2026 \
  --reason "competition window opened"
python3 -m services.attack_defense.cli ad tournament-status livectf-2026
```

For each `scheduled` fixture, deploy its generated Match instances through the
trusted runtime boundary, provision fresh fixture credentials, then start it:

```bash
python3 -m services.attack_defense.cli ad runtime-reconcile '<fixture-match-id>' \
  --runtime kubernetes --kube-context range-production --apply-kubernetes \
  --reason "deploy isolated LiveCTF fixture"
python3 -m services.attack_defense.cli ad tournament-fixture-start \
  livectf-2026 '<fixture-id>' --reason "teams and checker ready"
```

After the Match is complete, finalize it. Omit `--winner-entry-id` for normal
scoreboard selection; provide it only for a documented tie-break decision.

```bash
python3 -m services.attack_defense.cli ad tournament-fixture-finalize \
  livectf-2026 '<fixture-id>' --reason "fixture clock and disputes closed"
python3 -m services.attack_defense.cli ad tournament-reconcile livectf-2026 \
  --reason "recover and materialize next stage"
```

## Live Fire UI

When Match state includes `tournament_id`, Operator, Competitor and Observer
navigation gains **Tournament Bracket**. It shows only server-confirmed stages,
fixtures, advancement and scores. The operator view includes fixture Match IDs;
participant and observer views are broadcast-safe. An observer can also supply
`?tournament_id=livectf-2026` together with the fixture Match URL/configuration.

## Recovery and limitations

- Re-run `tournament-reconcile` after an API or operator-host restart. Stable IDs
  and uniqueness constraints prevent duplicate fixture Matches.
- A fixture cannot finalize until its Match is ended. A tied fixture requires
  an explicit referee winner and reason.
- The bundled static three-team Docker Compose demo does not dynamically create
  isolated tournament fixture containers. Database/bracket development works
  locally, but real fixture service deployment must use the existing
  Kubernetes runtime or an externally generated, reviewed Compose project.
- Starting/finalizing fixtures is operator controlled in this MVP. Automatic
  time-slot scheduling, credential issuance/rotation, check-in and no-show
  adjudication are production follow-ups.
- Do not reuse a fixture JWT, volume or management secret in a later stage.

