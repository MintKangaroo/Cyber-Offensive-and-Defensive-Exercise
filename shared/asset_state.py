"""
Authoritative asset-state fold (system-of-record derivation).

Asset state is derived from the durable event journal — this module is the Python
mirror of the client reducer in `dashboards/shared/src/events.ts` (`assetStates`), so
a checkpoint materialized server-side agrees exactly with what the live UI shows. It
folds ONLY the observed event stream; it never invents or recomputes authoritative
scores or config state. A checkpoint is this fold frozen at a journal position, giving
replay an authoritative anchor instead of defaulting pre-window assets to "unknown".
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping

ASSET_STATES = ("unknown", "under_attack", "compromised", "contained", "recovered")
_ATTACK_EVENTS = ("red_attack_started", "flag_exfiltrated")


def fold_asset_states(
    events: Iterable[Mapping[str, Any]],
    seed: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Fold events into per-asset state, mirroring the TypeScript ``assetStates``.

    ``seed`` is a prior checkpoint's states; events fold forward from it. Ordering is
    ``(timestamp, event_id)`` ascending, identical to the client reducer.
    """
    states: dict[str, str] = dict(seed or {})
    ordered = sorted(
        events,
        key=lambda e: (e.get("timestamp") or 0, str(e.get("event_id") or "")),
    )
    for event in ordered:
        asset = event.get("target_asset")
        if not asset:
            continue
        kind = event.get("event_type")
        if kind == "asset_compromised":
            states[asset] = "compromised"
        elif kind == "asset_recovered":
            states[asset] = "recovered"
        elif kind == "blue_block_success":
            states[asset] = "contained"
        elif kind in _ATTACK_EVENTS and states.get(asset) != "compromised":
            states[asset] = "under_attack"
    return states
