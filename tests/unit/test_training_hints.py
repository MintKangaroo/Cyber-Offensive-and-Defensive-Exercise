"""Policy-aware hint usage records (roadmap priority 3, part A).

Hints are revealed progressively, recorded per learner, gated by an instructor
policy, and surfaced as `hints_used` in the personal training profile — without
ever touching competition scores.
"""
import time

import jwt
import pytest
import yaml
from fastapi.testclient import TestClient

from services.challenge_portal import anticheat
from services.challenge_portal import main as portal
from shared import scope

SECRET = "training-hints-test-key-not-for-production-32-bytes-long"


def headers(actor="learner-one", team="alpha", match="exercise-one", role="red"):
    return {
        "Authorization": "Bearer "
        + jwt.encode(
            {"sub": actor, "role": role, "team_id": team, "match_id": match,
             "type": "access", "exp": time.time() + 120},
            SECRET, algorithm="HS256",
        )
    }


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("AUTH_JWT_SECRET", SECRET)
    monkeypatch.setenv("RANGE_SCOPE_ENFORCE", "true")
    monkeypatch.setattr(portal, "_AC_DB_PATH", tmp_path / "audit.db")
    monkeypatch.setattr(portal, "_SOLVES_PATH", tmp_path / "solves.json")
    monkeypatch.setattr(portal, "_SOLVES", {})
    monkeypatch.setattr(portal, "_BLUE_SOLVES", {})
    monkeypatch.setattr(portal, "_AC_STATE", anticheat.AntiCheatState())

    # A challenge whose definition carries red-task hints (never in the public catalog).
    cdir = tmp_path / "web" / "WEB-HINT"
    cdir.mkdir(parents=True)
    (cdir / "challenge.yaml").write_text(yaml.safe_dump({
        "challenge": {
            "id": "WEB-HINT", "title": "Hinted web", "category": "web",
            "difficulty": "easy",
            "red_task": {"goal": "x", "hints": [
                {"cost": 5, "text": "First: look at /api/version"},
                {"cost": 10, "text": "Second: the IDOR is on /api/notes/{id}"},
            ]},
        }
    }))
    monkeypatch.setattr(portal, "CATALOG", {
        "WEB-HINT": {"id": "WEB-HINT", "title": "Hinted web", "category": "web",
                     "difficulty": "easy", "points_red": 30, "dir": str(cdir)},
    })
    monkeypatch.setattr(portal, "BLUE_CATALOG", {})

    conn = portal._ac_db()
    anticheat.init_audit(conn)
    conn.close()

    async def verified(_):
        pass
    monkeypatch.setattr(scope, "verify_session", verified)
    return TestClient(portal.app)


def test_hints_require_membership(client):
    assert client.get("/portal/training/challenges/WEB-HINT/hints").status_code == 401
    assert client.post("/portal/training/challenges/WEB-HINT/hints/0/reveal").status_code == 401


def test_unrevealed_hint_text_is_never_exposed(client):
    r = client.get("/portal/training/challenges/WEB-HINT/hints", headers=headers())
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 2 and body["revealed_count"] == 0 and body["next_index"] == 0
    assert all(h["text"] is None for h in body["hints"])  # nothing revealed yet
    assert "look at /api/version" not in r.text


def test_progressive_reveal_records_and_returns_text(client):
    first = client.post("/portal/training/challenges/WEB-HINT/hints/0/reveal", headers=headers())
    assert first.status_code == 200
    assert first.json() == {
        "challenge_id": "WEB-HINT", "index": 0, "cost": 5,
        "text": "First: look at /api/version", "hints_used": 1,
    }
    second = client.post("/portal/training/challenges/WEB-HINT/hints/1/reveal", headers=headers())
    assert second.status_code == 200 and second.json()["hints_used"] == 2

    listing = client.get("/portal/training/challenges/WEB-HINT/hints", headers=headers()).json()
    assert listing["revealed_count"] == 2 and listing["next_index"] is None
    assert listing["hints"][0]["text"] == "First: look at /api/version"


def test_out_of_order_reveal_is_rejected(client):
    # index 1 before 0
    assert client.post("/portal/training/challenges/WEB-HINT/hints/1/reveal", headers=headers()).status_code == 409
    # out of range
    assert client.post("/portal/training/challenges/WEB-HINT/hints/9/reveal", headers=headers()).status_code == 404


def test_reveal_is_idempotent_per_index(client):
    client.post("/portal/training/challenges/WEB-HINT/hints/0/reveal", headers=headers())
    # revealing 0 again is a no-op reveal (still index 0, count stays 1 in listing)
    again = client.post("/portal/training/challenges/WEB-HINT/hints/0/reveal", headers=headers())
    assert again.status_code == 200
    listing = client.get("/portal/training/challenges/WEB-HINT/hints", headers=headers()).json()
    assert listing["revealed_count"] == 1


def test_hints_used_flows_into_personal_profile(client):
    client.post("/portal/training/challenges/WEB-HINT/hints/0/reveal", headers=headers())
    client.post("/portal/training/challenges/WEB-HINT/hints/1/reveal", headers=headers())
    me = client.get("/portal/training/me", headers=headers()).json()
    entry = next(a for a in me["activity"] if a["id"] == "WEB-HINT")
    assert entry["hints_used"] == 2
    assert "hint count" not in me["unavailable_inputs"]
    # competition scores untouched
    assert portal._SOLVES == {}


def test_instructor_policy_gates_hints(client):
    # a learner cannot set policy
    assert client.post("/portal/training/hints/policy", headers=headers(),
                       json={"enabled": False, "reason": "x"}).status_code == 403
    # instructor disables hints
    r = client.post("/portal/training/hints/policy", headers=headers(role="instructor"),
                    json={"enabled": False, "reason": "exam mode"})
    assert r.status_code == 200 and r.json()["enabled"] is False
    assert client.get("/portal/training/hints/policy", headers=headers()).json()["enabled"] is False
    # reveal is now blocked
    assert client.post("/portal/training/challenges/WEB-HINT/hints/0/reveal", headers=headers()).status_code == 403
    # re-enable restores it
    client.post("/portal/training/hints/policy", headers=headers(role="instructor"),
                json={"enabled": True, "reason": "practice"})
    assert client.post("/portal/training/challenges/WEB-HINT/hints/0/reveal", headers=headers()).status_code == 200
