# Scenario Studio: executable authoring and source fidelity

Open **Instructor → Scenario Studio** in Control Tower with an instructor identity.
The editor uses the existing scenario engine, source files and publication rules.
It does not execute attacks during validation or create external targets.

## Author an exercise

1. Open an existing scenario, keep the initial single-scenario draft, or choose
   **New crossover draft**. Save an edited draft before starting another one.
2. Set the briefing, existing range sector and exercise time limit.
3. For crossovers, append a phase with an explicit numeric ID, Red/Blue actor,
   workflow and completion dependency. Existing IDs are never renumbered.
4. Use event stages for observed operational transitions. Select the objective
   event, points, prerequisite stage and final-stage marker. Evidence criteria use
   the runner's existing dot paths, for example `metadata.vuln_id`, with typed JSON
   values. **Apply** or **Revert** criteria before saving or changing editor modes.
5. Use investigation objectives for submitted evidence. Give each objective an
   unambiguous name and submission key. Answer keys are instructor-only source data;
   blank keys mean no automatic objective points and require instructor review.
6. In a single scenario, add Blue detection/recovery objectives using the existing
   `match_event`, `match_alert`, `match`, `points` and `time_bonus` contract.
7. Validate and dry run. Inspect errors, warnings, actual phase execution order and
   projected event pacing. Correct dependencies before publication.
8. Save a private draft or publish after explicit confirmation and an audit reason.
   Active exercises cannot be overwritten. Concurrent changes require a fresh
   source revision; source text and publication audit remain persisted locally.

## Runtime semantics that the editor preserves

- The first crossover phase starts immediately. Subsequent phases unlock through
  `locked_until: phase_N_name.completed`. Numeric phase order controls execution;
  reordering YAML keys does not change that order.
- A final event stage completes its phase. The existing investigation runner also
  completes a phase after **all objectives have been submitted**, including
  incorrect submissions. Correct answers award objective points. This release
  documents that tested behavior; it does not silently change grading rules.
- Mixing event stages and investigation objectives creates alternative completion
  paths. Validation warns that these are not cumulative gates.
- `blue_parallel`, `completion_unlocks` and descriptive `success_criteria` are
  existing planning fields, not automatically executed rules in the current runner.
  The visual editor labels planning notes and validation reports this limitation.
- `expected_sec` is a dry-run pacing hint, not an enforced stage deadline. An
  investigation objective has no invented duration. The phase projection includes
  investigation counts and unlock/completion rules separately from event pacing.
- An embedded crisis-communications inject campaign (`injects_campaign:`) is authored
  visually and published with the scenario file (see below). Complex inject libraries,
  campaign templates and rubric grading review remain in the Injects workspace; they
  are not converted into fictional executable schema fields.

## Crisis-communications inject campaigns

A scenario can carry an optional `injects_campaign:` block so a timed sequence of
non-technical injects (media, exec, regulator, legal) is authored, versioned and
published through the **same lossless scenario file contract** as the rest of the
exercise — the missing publication contract that previously kept injects out of the
Studio. Because the campaign lives in the scenario, its `scenario_id` is bound to the
scenario's own id, giving referential integrity instead of a free-form string.

- **Add** a campaign, then add specs. Each spec has a `spec_id`, an optional built-in
  `template_id` (media-press-call, exec-ciso-brief, regulator-notice, legal-hold) or
  inline `subject`/`body`, a `channel`, `deadline_min`, an `at_sec` schedule and an
  optional `trigger` that fires a follow-up after an earlier spec is **answered** or
  its **deadline is missed**.
- **Rubric** criteria (`{criterion, max}`) are authored per spec. Grading stays
  **manual**: an instructor awards points per criterion at run time. The editor does
  not invent automatic scoring.
- **Validation** applies the injects runtime's own rules from
  `shared/injects_campaign.py` (unique spec ids, existing/valid triggers, positive
  deadlines and rubric caps). Anything the runtime would reject is an error here too;
  unknown templates, forward triggers and empty inline injects are warnings.
- **Launch**: after publishing, `POST /command/injects/campaign/launch` reads the
  embedded campaign from the published scenario and loads it into the injects service
  with the scenario id already attached. Invalid campaigns are refused before launch.

Honest limits: the built-in inject **template library has no publish endpoint** —
new reusable templates are still added in source or inlined per spec — and rubric
grading is reviewed by an instructor, not scored automatically.

## Fidelity and validation

Switching Visual ↔ YAML never serializes the source. Explicit visual edits modify
YAML nodes and preserve other documents, comments and unknown fields. Applying an
entire evidence-criteria object explicitly replaces that object. Invalid/incomplete
criteria remain local until corrected or reverted; they cannot be silently omitted
by saving or switching modes. Invalid existing sequence fields require correction
in source mode instead of destructive replacement.

Backend validation uses the runtime loader and checks phase prerequisites, duplicate
numeric phase IDs, per-phase stage references, ambiguous objective aliases, and
negative crossover durations. Investigation-only exercises are accepted. Projection
uses the same numeric phase order as the runner. Legacy description-only phases are
reported with warnings rather than being silently rewritten.

Regression tests edit every shipped single/crossover scenario and compare its
remaining parsed semantics. Browser tests cover explicit creation, source round
trips, pending criteria, keyboard activation and automated tablet accessibility.
