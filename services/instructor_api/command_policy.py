"""Explicit command-plane capabilities and telemetry projections.

The legacy exercise plane and A/D plane are distinct. Never grant instructor
capabilities to an A/D operator or expose unscoped SOC sources to competitors.
"""

from __future__ import annotations
import json
from shared.rbac import Identity

BASE = {"overview", "digital-twin", "events", "competition", "challenges", "training"}
CAPABILITIES = {
    "instructor": BASE
    | {
        "incidents",
        "soc",
        "scenarios",
        "replay",
        "aar",
        "injects",
        "services",
        "audit",
        "control",
        "teams",
        "scoring",
        "copilot",
        "policy",
    },
    "blue": BASE | {"incidents", "injects", "replay", "copilot"},
    "red": BASE | {"injects", "replay", "copilot"},
    "observer": {"overview", "digital-twin", "events", "competition"},
    "competitor": {"overview", "competition", "challenges", "training", "copilot"},
    "operator": {"overview", "competition"},
}
PUBLIC_EVENTS = {
    "asset_compromised",
    "asset_recovered",
    "scenario_started",
    "scenario_ended",
    "stage_completed",
}


def capabilities(identity: Identity) -> list[str]:
    return sorted(CAPABILITIES.get(identity.role, set()))


def metadata(event: dict) -> dict:
    value = event.get("metadata") or {}
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            value = {}
    return value if isinstance(value, dict) else {}


def project_event(
    event: dict, identity: Identity, *, now: float, delay: float = 30
) -> dict | None:
    """Fail closed for absent scope; observers get delayed, allowlisted fields only."""
    if not isinstance(event, dict):
        return None
    md = metadata(event)
    if identity.role == "instructor":
        return {**event, "metadata": md}
    if identity.role in {"operator", "competitor"}:
        return None  # these roles use the A/D engine's tested projections
    match = md.get("match_id") or event.get("match_id")
    if identity.match_id and match and match != identity.match_id:
        return None
    if identity.role in {"red", "blue"}:
        if not identity.team_id or event.get("team_id") != identity.team_id:
            return None
        if (
            identity.match_id
            and not match
            and event.get("scenario_id") != identity.match_id
        ):
            return None
        if identity.role == "red" and event.get("actor") != "red":
            return None
        return {**event, "metadata": md}
    if identity.role == "observer":
        if (
            identity.match_id
            and event.get("scenario_id") != identity.match_id
            and match != identity.match_id
        ):
            return None
        ts = event.get("timestamp")
        if not isinstance(ts, (int, float)) or ts > now - delay:
            return None
        if event.get("event_type") not in PUBLIC_EVENTS:
            return None
        return {
            k: event[k]
            for k in (
                "event_id",
                "event_type",
                "timestamp",
                "target_asset",
                "scenario_id",
                "actor",
            )
            if k in event
        } | {"metadata": {}}
    return None


def scope_incidents(rows: list[dict], identity: Identity) -> list[dict]:
    if identity.role == "instructor":
        return rows
    if identity.role == "blue" and identity.team_id:
        return [r for r in rows if r.get("team_id") == identity.team_id]
    return []
