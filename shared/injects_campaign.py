"""
Injects campaign contract — pure validation (single source of truth)
====================================================================
An injects *campaign* is a timed/triggered sequence of non-technical crisis
injects (media/exec/regulator/legal ...). Historically campaigns could only be
authored imperatively by POSTing to the running injects service. This module is
the one place that defines *what a valid campaign definition is*, so the same
rules govern:

  * the injects runtime (execution — `services/injects/`), and
  * Scenario Studio (authoring — `services/scenario_engine/studio.py`), where a
    campaign is embedded in a scenario source document under `injects_campaign:`
    and published through the existing lossless scenario file contract.

`campaign_issues` never raises; it returns a list of issue dicts in the same
`{level, code, message, where}` shape the Studio validator already emits, so
authoring diagnostics and the runtime agree on the contract. Errors here are a
superset of what the runtime rejects: anything the runtime would refuse is an
error here too, plus authoring-quality warnings that never change execution.
"""
from __future__ import annotations

from typing import Any

# Canonical contract constants. `services/injects/model.py` and
# `services/injects/engine.py` re-export these so the runtime and the authoring
# validator can never drift.
CHANNELS = ("media", "exec", "regulator", "legal", "customer", "internal")
TRIGGER_EVENTS = ("answered", "deadline_missed")


def _issue(level: str, code: str, message: str, where: str) -> dict:
    return {"level": level, "code": code, "message": message, "where": where}


def _positive_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0


def rubric_issues(rubric: Any, where: str) -> list[dict]:
    """Validate a rubric — a flat list of ``{criterion, max}`` with positive caps.

    Grading stays manual (an instructor awards points per criterion); this only
    checks the shape so a published campaign cannot carry an ungradeable rubric.
    """
    if not isinstance(rubric, list):
        return [_issue("error", "rubric_shape", "rubric must be a list of {criterion, max}.", where)]
    issues: list[dict] = []
    for i, item in enumerate(rubric):
        at = f"{where}.rubric[{i}]"
        if not isinstance(item, dict):
            issues.append(_issue("error", "rubric_item", "Each rubric item is a mapping with criterion and max.", at))
            continue
        crit = item.get("criterion")
        if not isinstance(crit, str) or not crit.strip():
            issues.append(_issue("error", "rubric_criterion", "A rubric criterion must be a nonempty label.", at))
        if not _positive_number(item.get("max")):
            issues.append(_issue("error", "rubric_max", "A rubric criterion needs a positive point cap.", at))
    return issues


def campaign_issues(campaign: Any, *, library_ids: frozenset[str] | set[str] = frozenset()) -> list[dict]:
    """Validate an embedded ``injects_campaign`` mapping (``{name, specs: [...]}``).

    ``library_ids`` are the built-in template ids; when known, a ``template_id``
    outside them is warned about (the runtime silently uses inline fields).
    """
    if not isinstance(campaign, dict):
        return [_issue("error", "campaign_shape", "injects_campaign must be a mapping.", "injects_campaign")]

    issues: list[dict] = []
    name = campaign.get("name")
    if not isinstance(name, str) or not name.strip():
        issues.append(_issue("error", "campaign_name", "The campaign needs a nonempty name.", "injects_campaign.name"))

    specs = campaign.get("specs")
    if not isinstance(specs, list) or not specs:
        issues.append(_issue("error", "campaign_specs", "A campaign needs at least one inject spec.", "injects_campaign.specs"))
        return issues

    # First pass: collect spec_ids and flag identity problems.
    ids: list[str | None] = []
    seen: set[str] = set()
    for i, spec in enumerate(specs):
        at = f"injects_campaign.specs[{i}]"
        if not isinstance(spec, dict):
            issues.append(_issue("error", "spec_shape", "Each spec is a mapping.", at))
            ids.append(None)
            continue
        sid = spec.get("spec_id")
        if not isinstance(sid, str) or not sid.strip():
            issues.append(_issue("error", "spec_id", "Each spec needs a nonempty spec_id.", f"{at}.spec_id"))
            ids.append(None)
        elif sid in seen:
            issues.append(_issue("error", "duplicate_spec", f"Duplicate spec_id: {sid}.", f"{at}.spec_id"))
            ids.append(sid)
        else:
            seen.add(sid)
            ids.append(sid)

    # Second pass: per-spec content and trigger referential integrity.
    for i, spec in enumerate(specs):
        if not isinstance(spec, dict):
            continue
        at = f"injects_campaign.specs[{i}]"
        sid = ids[i]
        tpl = spec.get("template_id")
        has_template = isinstance(tpl, str) and tpl != ""
        if has_template and library_ids and tpl not in library_ids:
            issues.append(_issue(
                "warning", "unknown_template",
                f"template_id '{tpl}' is not in the built-in library; only inline fields are delivered.",
                f"{at}.template_id",
            ))

        channel = spec.get("channel")
        if channel is not None and channel not in CHANNELS:
            issues.append(_issue("warning", "unknown_channel", f"channel '{channel}' is outside {CHANNELS}.", f"{at}.channel"))

        if not has_template:
            for field in ("subject", "body"):
                value = spec.get(field)
                if not isinstance(value, str) or not value.strip():
                    issues.append(_issue(
                        "warning", "empty_inject",
                        f"Without a template_id, {field} should be provided or the team receives an empty inject.",
                        f"{at}.{field}",
                    ))

        deadline = spec.get("deadline_min")
        if deadline is not None and not _positive_number(deadline):
            issues.append(_issue("error", "bad_deadline", "deadline_min must be a positive number of minutes.", f"{at}.deadline_min"))

        at_sec = spec.get("at_sec")
        if at_sec is not None and (not isinstance(at_sec, (int, float)) or isinstance(at_sec, bool) or at_sec < 0):
            issues.append(_issue("error", "bad_at_sec", "at_sec must be a nonnegative number of seconds.", f"{at}.at_sec"))

        if "rubric" in spec:
            issues.extend(rubric_issues(spec.get("rubric"), at))
        elif not has_template:
            issues.append(_issue(
                "warning", "no_rubric",
                "No rubric: the response is only marked on time or late, never scored.",
                at,
            ))

        trigger = spec.get("trigger")
        if trigger is not None:
            tat = f"{at}.trigger"
            if not isinstance(trigger, dict):
                issues.append(_issue("error", "trigger_shape", "trigger must be a mapping with after and on.", tat))
            else:
                after = trigger.get("after")
                on = trigger.get("on", "answered")
                if after not in seen:
                    issues.append(_issue("error", "trigger_after", f"trigger.after '{after}' is not an existing spec_id.", tat))
                elif after == sid:
                    issues.append(_issue("error", "self_trigger", "A spec cannot be triggered by itself; it would never fire.", tat))
                elif after in ids and ids.index(after) > i:
                    issues.append(_issue(
                        "warning", "forward_trigger",
                        "trigger.after appears later in the list; it still fires, but order specs causally for a readable timeline.",
                        tat,
                    ))
                if on not in TRIGGER_EVENTS:
                    issues.append(_issue("error", "trigger_on", f"trigger.on must be one of {TRIGGER_EVENTS}.", tat))

    return issues
