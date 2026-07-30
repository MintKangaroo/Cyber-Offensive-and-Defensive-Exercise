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
repeated initialization, checks, submissions and scoring safe. A lease prevents
two local workers from ticking the same Match simultaneously.

Persisted runtime jobs use the same recovery principle. A job left `running`
past the larger validation/deployment timeout is eligible for atomic reclaim;
the new owner and incremented attempt are recorded. Runtime operations and
completion handlers remain idempotent, so a host-runner restart does not require
editing the database.

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

## Metrics

Scrape `:8100/metrics`. Required metrics include current/duration rounds, flag
issue/injection/submission, check count/latency, patch submission/validation/
deployment, score events, runtime operations and engine errors. Correlation IDs
belong in logs/audit, not labels.

## Score disputes

Use the operator ledger/audit views, then call round or Match recalculation.
Identical evidence produces no new entry. If an operator correction is needed,
use adjustment with a precise reason. Never update ledger rows.

## Backup and rollback

Stop only the additive service and archive `ad_data`. Restore its
`attack_defense.db` plus WAL files as a consistent set. Exercise mode continues
using its existing stores. Compose teardown of A/D services must not remove
legacy volumes.
