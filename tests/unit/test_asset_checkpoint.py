"""Authoritative asset-state checkpoints (roadmap priority 4, part A).

The collector folds the durable journal into a per-asset checkpoint frozen at a
journal position, so replay can anchor to it instead of guessing pre-window state.
Only the derived asset-state fold is materialized — scores/config are untouched.
"""
import json
import time

import jwt
import pytest
from fastapi.testclient import TestClient

from shared import scope

SECRET = "checkpoint-test-signing-key-32-bytes-long-x"  # training-only fixture
MASTER = "checkpoint-test-service-master"  # training-only fixture


def auth(role="blue", team="alpha", scenario="exercise-a"):
    return {"Authorization": "Bearer " + jwt.encode(
        {"sub": role + "-user", "role": role, "team_id": team, "match_id": scenario,
         "type": "access", "exp": time.time() + 120}, SECRET, algorithm="HS256")}


SERVICE = {"Authorization": "Bearer " + MASTER}


@pytest.fixture
def collector(monkeypatch, tmp_path):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("RANGE_SCOPE_ENFORCE", "true")
    monkeypatch.setenv("AUTH_JWT_SECRET", SECRET)
    monkeypatch.setenv("SERVICE_TOKEN", MASTER)
    monkeypatch.setenv("INSTRUCTOR_TOKEN", "checkpoint-test-instructor")
    monkeypatch.delenv("RBAC_TOKENS", raising=False)
    monkeypatch.delenv("RBAC_ALLOW_INSECURE_DEV", raising=False)

    async def verified(_):
        pass
    monkeypatch.setattr(scope, "verify_session", verified)

    from services.event_collector import main as mod
    monkeypatch.setattr(mod, "DB_PATH", tmp_path / "events.db")
    monkeypatch.setattr(mod, "_writer_conn", None)
    mod.init_db()
    yield mod, TestClient(mod.app)
    if mod._writer_conn:
        mod._writer_conn.close()


def _persist(mod, records):
    from shared.event_schema import Event
    events = [
        Event(
            event_id=r["event_id"], event_type=r.get("event_type", "asset_compromised"),
            timestamp=r["timestamp"], actor=r.get("actor", "red"),
            team_id="alpha", scenario_id="exercise-a",
            target_asset=r.get("target_asset", "power_plant"), metadata={},
        )
        for r in records
    ]
    assert all(mod._persist_batch(events))


def test_checkpoint_creation_requires_service_or_instructor(collector):
    mod, client = collector
    _persist(mod, [{"event_id": "c1", "timestamp": 100}])
    # a plain member cannot materialize a checkpoint
    assert client.post("/replay/checkpoint?scenario_id=exercise-a", headers=auth()).status_code in {401, 403}
    # a service token can
    assert client.post("/replay/checkpoint?scenario_id=exercise-a", headers=SERVICE).status_code == 200


def test_checkpoint_folds_authoritative_asset_state(collector):
    mod, client = collector
    _persist(mod, [
        {"event_id": "a", "event_type": "red_attack_started", "timestamp": 100},
        {"event_id": "b", "event_type": "asset_compromised", "timestamp": 110},
    ])
    made = client.post("/replay/checkpoint?scenario_id=exercise-a", headers=SERVICE).json()
    assert made["states"] == {"power_plant": "compromised"}
    assert made["at_ts"] == 110
    # a scoped member can read the checkpoint back
    got = client.get("/replay/checkpoint?scenario_id=exercise-a", headers=auth()).json()
    assert got["checkpoint"]["states"] == {"power_plant": "compromised"}


def test_checkpoint_is_incremental_and_time_anchored(collector):
    mod, client = collector
    _persist(mod, [{"event_id": "a", "event_type": "asset_compromised", "timestamp": 100}])
    client.post("/replay/checkpoint?scenario_id=exercise-a", headers=SERVICE)
    _persist(mod, [{"event_id": "b", "event_type": "asset_recovered", "timestamp": 200}])
    second = client.post("/replay/checkpoint?scenario_id=exercise-a", headers=SERVICE).json()
    assert second["states"] == {"power_plant": "recovered"}  # seeded from the first checkpoint
    # time anchoring: at<=150 returns the earlier (compromised) checkpoint
    early = client.get("/replay/checkpoint?scenario_id=exercise-a&at=150", headers=auth()).json()
    assert early["checkpoint"]["states"] == {"power_plant": "compromised"}
    late = client.get("/replay/checkpoint?scenario_id=exercise-a&at=250", headers=auth()).json()
    assert late["checkpoint"]["states"] == {"power_plant": "recovered"}


def test_auto_checkpoint_threshold_logic(collector):
    mod, _ = collector
    counters: dict = {}
    # below threshold: nothing due, counters advance
    assert mod.checkpoints_due(["exercise-a", "exercise-a"], 3, counters) == set()
    assert counters["exercise-a"] == 2
    # crossing the threshold marks the scenario due and resets its counter
    assert mod.checkpoints_due(["exercise-a"], 3, counters) == {"exercise-a"}
    assert counters["exercise-a"] == 0
    # None scenario ids and every<=0 are ignored
    assert mod.checkpoints_due([None, "x"], 1, counters) == {"x"}
    assert mod.checkpoints_due(["exercise-a"], 0, counters) == set()


def test_reset_invalidates_checkpoints(collector):
    mod, client = collector
    _persist(mod, [{"event_id": "a", "event_type": "asset_compromised", "timestamp": 100}])
    client.post("/replay/checkpoint?scenario_id=exercise-a", headers=SERVICE)
    assert client.get("/replay/checkpoint?scenario_id=exercise-a", headers=auth()).json()["checkpoint"]
    # instructor reset bumps the journal revision → prior checkpoints are stale
    r = client.post("/admin/reset", headers={"Authorization": "Bearer checkpoint-test-instructor"},
                    json={"confirm": True, "reason": "reset for checkpoint test"})
    assert r.status_code == 200 and "asset_checkpoints" in r.json()["cleared"]
    assert client.get("/replay/checkpoint?scenario_id=exercise-a", headers=auth()).json()["checkpoint"] is None
