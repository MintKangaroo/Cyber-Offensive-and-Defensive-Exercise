# Attack/Defense Operations

## Lifecycle

1. Create a Match with `attack_defense` or `hybrid_live_fire`.
2. Register at least two teams and one or more service definitions.
3. Ensure declared Compose instances are healthy.
4. Start the Match. The first tick creates and initializes round 1.
5. Monitor `/health`, `/metrics`, operator checker/flag views and runtime jobs.
6. Pause/resume with an audit reason when infrastructure, rather than a team,
   causes material impairment.
7. Finalize or extend a round only after documenting impact.
8. End the Match, archive the database and produce AAR evidence.

## Recovery and idempotency

On process restart, startup scans persisted running matches. The current round
state is resumed. Stable IDs, unique constraints and score snapshots make
repeated initialization, checks, submissions and scoring safe. SQLite uses a
persisted lease; PostgreSQL HA holds a session advisory lock for the entire
Match tick.

Persisted runtime jobs use the same recovery principle. A job left `running`
past the larger validation/deployment timeout is eligible for atomic reclaim;
the new owner, incremented attempt and fencing token are recorded. PostgreSQL
workers use `FOR UPDATE SKIP LOCKED`. Runtime operations and completion handlers
remain idempotent, so a host-runner restart does not require editing the
database.

## PostgreSQL HA mode

The optional profile runs two API/game-engine replicas on shared PostgreSQL and
a loopback HAProxy endpoint on port 8110. It preserves the default SQLite mode
and must be initialized as a separate deployment. Start, verify and recover it
using [High-Availability Mode](attack-defense-high-availability.md).

```bash
export ATTACK_DEFENSE_API_URL=http://localhost:8110
python3 -m services.attack_defense.cli ad ha-status
curl -fsS http://localhost:8110/ready
```

If a round repeatedly fails, inspect operator audit and checker errors. Do not
manually edit score totals. Repair the dependency and tick again, or force
finalization. `checker_system_error` is excluded from team availability
eligibility.

## Patch runner

The API performs registry/policy validation and queues sandbox work. From the
trusted host:

```bash
export INSTRUCTOR_TOKEN=dev-instructor-token
python3 -m services.attack_defense.cli ad runtime-work \
  --compose-file docker-compose.yml \
  --project cyber-range-platform
```

Run repeatedly or under a host service timer. The sequence is sandbox replace,
hidden functional/flag check, live replace, post-deploy check, and automatic
rollback. Never mount Docker's socket into `attack_defense`.

For Kubernetes, preview and reconcile live services before starting the match:

```bash
python3 -m services.attack_defense.cli ad runtime-reconcile ad-demo \
  --runtime kubernetes --kube-context range-production
python3 -m services.attack_defense.cli ad runtime-reconcile ad-demo \
  --runtime kubernetes --kube-context range-production --apply-kubernetes \
  --reason "initial tournament deployment"
```

Then run `runtime-work` with the same context and `--apply-kubernetes`. The API
must be reachable from the host runner, while checker/management traffic must
originate from the labelled management plane. Full prerequisites and recovery
limits are in [Kubernetes Runtime](attack-defense-kubernetes.md).

## Metrics

Scrape `:8100/metrics`. Required metrics include current/duration rounds, flag
issue/injection/submission, check count/latency, patch submission/validation/
deployment, score events, runtime operations and engine errors. Correlation IDs
belong in logs/audit, not labels.

## Sanitized capture delivery

An approved sensor or operator supplies classic-PCAP bytes; the A/D API does not
open host interfaces or capture traffic itself. Upload with a reason, then
confirm the artifact's redaction count, packet count, hash and release time:

```bash
python3 -m services.attack_defense.cli ad capture-upload \
  ad-demo ./round-042.pcap --reason "round 42 post-round evidence"
python3 -m services.attack_defense.cli ad capture-list ad-demo
```

Monitor `capture_ingest` rejections and sanitized storage capacity. Do not copy
raw captures into `ad_data`. A competitor receives a team-specific watermarked
copy only after the server release gate. Full policy and limits are documented
in [PCAP Privacy and Delayed Delivery](attack-defense-pcap.md).

## Score disputes

Use the operator ledger/audit views, then call round or Match recalculation.
Identical evidence produces no new entry. If an operator correction is needed,
use adjustment with a precise reason. Never update ledger rows.

## Backup and rollback

For SQLite, stop only the additive service and archive `ad_data`. Restore its
database, WAL files and sanitized `captures/` directory as a consistent set.
For PostgreSQL, restore a tested database backup/PITR point and its matching
artifact store. Exercise mode continues using its existing stores. Compose
teardown of A/D services must not remove legacy or HA volumes.

## Optional KOTH operations

Configure KOTH while the Match is still in draft, or pause it before changing
an existing policy. A reason is always required:

```bash
python3 -m services.attack_defense.cli ad koth-configure ad-demo \
  --service-id notes --service-id vault \
  --lease-rounds 2 --points-per-round 3 --weight 1 \
  --reason "enable two service hills"
python3 -m services.attack_defense.cli ad koth-status ad-demo
```

To disable it safely, pause the Match and run:

```bash
python3 -m services.attack_defense.cli ad koth-configure ad-demo \
  --disable --reason "incident containment"
```

Configuration changes start a new activation epoch. Existing lease history is
retained for evidence but cannot reactivate. Investigate ownership and scoring
from operator KOTH state, audit events and the append-only ledger; never edit
lease or score rows manually. See [KOTH Policy](attack-defense-koth.md).

## Optional Stealth operations

Pause a running Match before enabling, disabling or changing Stealth:

```bash
python3 -m services.attack_defense.cli ad stealth-configure ad-demo \
  --alert-delay-rounds 2 --detection-window-rounds 2 \
  --attacker-points 2 --defender-points 2 \
  --reason "approved delayed disclosure policy"
python3 -m services.attack_defense.cli ad stealth-status ad-demo
```

Monitor the operator state, `stealth_incident` and
`stealth_detection_report` audit events, report rate limits and the three
`attack_defense_stealth_*` metrics. Do not disclose operator incident output to
competitors or broadcast systems: it contains attacker/victim attribution and
internal match decisions.

Participant report responses are deliberately non-oracular. Adjudicate report
quality from the external SIEM/EDR record referenced by its SHA-256, not from a
participant screenshot or repeated API submissions. Use an audited score
adjustment only after documented referee review. See
[Stealth Mode Policy](attack-defense-stealth.md).
