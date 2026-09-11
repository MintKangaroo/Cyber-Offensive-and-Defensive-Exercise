"""Pure asset-state fold — must mirror the client reducer in events.ts (assetStates)."""
from shared.asset_state import fold_asset_states


def _ev(i, kind, asset="power_plant", ts=None):
    return {"event_id": str(i), "event_type": kind, "target_asset": asset,
            "timestamp": i if ts is None else ts}


def test_transitions_match_the_client_reducer():
    events = [
        _ev(0, "red_attack_started"),
        _ev(1, "asset_compromised"),
        _ev(2, "blue_block_success", asset="ground_station"),
        _ev(3, "asset_recovered", asset="ground_station"),
    ]
    assert fold_asset_states(events) == {
        "power_plant": "compromised",
        "ground_station": "recovered",
    }


def test_under_attack_never_overrides_compromised():
    # compromise wins even if an attack event sorts later
    events = [_ev(0, "asset_compromised"), _ev(1, "red_attack_started")]
    assert fold_asset_states(events)["power_plant"] == "compromised"
    # but a plain attack with no compromise is under_attack
    assert fold_asset_states([_ev(0, "flag_exfiltrated")]) == {"power_plant": "under_attack"}


def test_ordering_is_by_timestamp_then_event_id():
    # recover(ts=5) then compromise(ts=10) → compromised is last
    events = [_ev("b", "asset_recovered", ts=5), _ev("a", "asset_compromised", ts=10)]
    assert fold_asset_states(events)["power_plant"] == "compromised"


def test_seed_anchors_prehistory_state():
    # With no in-window events, the asset keeps its checkpoint (seed) state, not "unknown".
    assert fold_asset_states([], seed={"power_plant": "compromised"}) == {"power_plant": "compromised"}
    # events fold forward from the seed
    folded = fold_asset_states([_ev(0, "asset_recovered")], seed={"power_plant": "compromised"})
    assert folded["power_plant"] == "recovered"


def test_events_without_asset_are_ignored():
    assert fold_asset_states([{"event_id": "x", "event_type": "asset_compromised"}]) == {}
