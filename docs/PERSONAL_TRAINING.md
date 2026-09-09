# Personal training evidence

Control Tower's **Training** page now distinguishes individual observations from
team completion. The challenge portal remains the grading authority. Personal
coverage, practice timing and recommendations never mutate competition points,
team solve ownership, dynamic scoring, A/D rounds or Stealth disclosure.

## What is measured

With `RANGE_SCOPE_ENFORCE=true`, an evaluated Red or Blue submission records the
verified actor alongside the existing anti-cheat audit. Personal reads require the
same actor, team, exercise and side. Another team member's success does not become
your personal completion. A personal pass may be recorded even when the team already
solved the challenge; the existing team scoring rules still prevent a second award.

**Start practice and open challenge** records an explicit start for that exercise,
actor, team, challenge and side. Repeated visits preserve the first start. Where a
subsequent successful evaluated submission exists, elapsed time is first pass minus
start. This is wall-clock time including idle time, not active working time. A pass
before the recorded start has unavailable duration, never a negative or guessed one.

Domain coverage is the number of personally passed catalog challenges divided by
the number available in that role's catalog. The UI calls it completion coverage,
not mastery. Eight named domains use explicit catalog categories; unknown category
mappings are not guessed. Recommendations prefer unfinished challenges with recorded
attempts, then published difficulty and challenge ID. The ordering is deterministic.

Hint usage, active working time, detection/response quality and attribution of older
attempts remain unavailable. A reviewed rubric and policy-aware hint instrumentation
are required before those can contribute to a fuller skill model. No AI judgment is
used in the current profile or competition scorer.

## Contracts and access

| Endpoint | Behavior |
|---|---|
| `GET /portal/training/me` | Personal profile, domains, activity and recommendations for the authenticated Red/Blue membership |
| `POST /portal/training/challenges/{cid}/start` | Idempotent start for an existing challenge in that role's catalog |
| `GET /command/training` | Existing team result plus additive `individual` source envelope |
| `POST /command/training/challenges/{cid}/start` | Membership-checked forwarding with the caller's credential |

Personal endpoints independently fail closed in both local compatibility and strict
deployment profiles. Static tokens without membership, observers and unassigned
identities cannot read or create personal records. JWTs undergo revocation checks.
Caller-supplied subject/team query values cannot select another person's data. Flags,
answer hashes, grader internals and another learner's submissions are not returned.
The Red grader's effective team cannot be overwritten by a nested submitted field.

Verified attempt capture requires the receiving-service scope enforcement path.
The compatibility profile reports that capture is disabled and does not relabel
unverified submissions as trusted observations. If the personal source is unavailable,
Command retains the existing team response and labels the fallback explicitly.

## Storage and migration

The existing portal `anticheat.db` gains nullable `submissions.verified_subject`, a
composite lookup index and `training_starts`. Migration preserves old audit rows;
their personal attribution remains null. The normal portal data volume persists
these records. Existing `portal_solves.json` attribution and score APIs are retained.
No frontend cache is used as authoritative completion or timing evidence.

Back up the portal data volume using the existing operational backup procedure.
Rolling back code can leave the added nullable column/table in place; do not erase
existing anti-cheat evidence to undo a UI migration. Profiles currently cover one
authenticated exercise membership, not a cross-organization learner dossier.

The isolated service-scope Docker drill exercises real login, explicit practice
start, a real failed challenge grade, personal reads, cross-role denial and token
revocation with fresh data. Unit tests also cover legacy migration, actor/team/match
isolation, repeated passes, missing timing, and competition-score independence.
