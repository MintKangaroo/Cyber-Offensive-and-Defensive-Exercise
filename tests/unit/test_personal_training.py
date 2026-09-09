import json
import sqlite3
import time
from types import SimpleNamespace

import jwt
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from services.challenge_portal import anticheat, training
from services.challenge_portal import main as portal
from shared import scope
from shared.rbac import Identity

SECRET = "personal-training-test-key-not-for-production-32-bytes"  # training-only fixture
CATALOG = {
    "WEB-001": {
        "id": "WEB-001",
        "title": "Range web evidence",
        "category": "web",
        "difficulty": "easy",
        "points_red": 30,
        "dir": "/tmp/isolated-test-challenge",
    },
    "ICS-001": {
        "id": "ICS-001",
        "title": "Range OT evidence",
        "category": "ics",
        "difficulty": "hard",
        "points_red": 40,
    },
}


def headers(actor="learner-one", team="alpha", match="exercise-one", role="red"):
    return {
        "Authorization": "Bearer "
        + jwt.encode(
            {
                "sub": actor,
                "role": role,
                "team_id": team,
                "match_id": match,
                "type": "access",
                "exp": time.time() + 120,
            },
            SECRET,
            algorithm="HS256",
        )
    }


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("AUTH_JWT_SECRET", SECRET)
    monkeypatch.setenv("RANGE_SCOPE_ENFORCE", "true")
    monkeypatch.setenv("RED_TOKEN", "training-static-red-test")
    monkeypatch.setattr(portal, "_AC_DB_PATH", tmp_path / "audit.db")
    monkeypatch.setattr(portal, "_SOLVES_PATH", tmp_path / "solves.json")
    monkeypatch.setattr(portal, "_SOLVES", {})
    monkeypatch.setattr(portal, "_BLUE_SOLVES", {})
    monkeypatch.setattr(portal, "_AC_STATE", anticheat.AntiCheatState())
    monkeypatch.setattr(portal, "CATALOG", CATALOG)
    monkeypatch.setattr(
        portal,
        "BLUE_CATALOG",
        {
            "DET-001": {
                "id": "DET-001",
                "title": "Detection",
                "category": "detection",
                "difficulty": "medium",
            }
        },
    )
    conn = portal._ac_db()
    anticheat.init_audit(conn)
    conn.close()

    async def verified(_):
        pass

    monkeypatch.setattr(scope, "verify_session", verified)
    monkeypatch.setattr(portal, "_emit_solve", lambda *args: verified(None))
    return TestClient(portal.app)


def attempt(
    subject="learner-one",
    team="exercise-one::alpha",
    match="exercise-one",
    side="red",
    passed=False,
    ts=100,
    cid="WEB-001",
):
    conn = portal._ac_db()
    try:
        anticheat.record(
            anticheat.AntiCheatState(),
            conn,
            team,
            match,
            cid,
            side,
            "opaque-test-hash",
            passed,
            ts,
            anticheat.Config(),
            verified_subject=subject,
        )
    finally:
        conn.close()


def test_migration_preserves_unattributed_legacy_audit():
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE submissions(id INTEGER PRIMARY KEY, ts REAL, team_id TEXT, match_id TEXT, cid TEXT, side TEXT, passed INTEGER, value_hash TEXT)"
    )
    conn.execute(
        "INSERT INTO submissions VALUES(1,10,'alpha','old','WEB-001','red',1,'opaque-test-hash')"
    )
    anticheat.init_audit(conn)
    anticheat.init_audit(conn)
    row = conn.execute("SELECT passed,verified_subject FROM submissions").fetchone()
    assert row == (1, None)
    conn.close()


@pytest.mark.parametrize("enforced", ["true", "false"])
def test_personal_routes_fail_closed_in_both_profiles(client, monkeypatch, enforced):
    monkeypatch.setenv("RANGE_SCOPE_ENFORCE", enforced)
    for path in ("/portal/training/me", "/portal/training/challenges/WEB-001/start"):
        response = client.post(path) if path.endswith("start") else client.get(path)
        assert response.status_code == 401
    assert (
        client.get(
            "/portal/training/me",
            headers={"Authorization": "Bearer training-static-red-test"},
        ).status_code
        == 403
    )
    assert (
        client.get("/portal/training/me", headers=headers(role="observer")).status_code
        == 403
    )


def test_profile_is_scoped_to_person_team_exercise_and_side(client):
    attempt(passed=True)
    attempt(ts=101)
    attempt(subject="another-learner", passed=True, cid="ICS-001")
    attempt(team="exercise-one::bravo", passed=True, cid="ICS-001")
    attempt(match="another-exercise", passed=True, cid="ICS-001")
    attempt(side="blue", passed=True, cid="ICS-001")
    attempt(subject=None, passed=True, cid="ICS-001")
    response = client.get(
        "/portal/training/me?team_id=bravo&subject=another-learner", headers=headers()
    )
    result = response.json()
    assert response.status_code == 200
    assert result["subject"] == "learner-one"
    assert len(result["activity"]) == 1
    assert result["activity"][0]["attempts"] == 2
    assert result["activity"][0]["elapsed_sec"] is None
    assert result["activity"][0]["hints_used"] is None
    assert result["recommendations"][0]["id"] == "ICS-001"
    assert "value_hash" not in response.text and "another-learner" not in response.text


def test_blue_profile_uses_defensive_catalog_and_original_audit_namespace(client):
    attempt(team="alpha", side="blue", cid="DET-001", passed=True)
    result = client.get("/portal/training/me", headers=headers(role="blue")).json()
    assert result["side"] == "blue"
    assert result["activity"][0]["id"] == "DET-001"
    assert (
        next(d for d in result["domains"] if d["domain"] == "Detection")["completed"]
        == 1
    )
    assert (
        client.post(
            "/portal/training/challenges/WEB-001/start", headers=headers(role="blue")
        ).status_code
        == 404
    )


def test_explicit_start_is_idempotent_and_elapsed_uses_first_pass(client):
    first = client.post(
        "/portal/training/challenges/WEB-001/start", headers=headers()
    ).json()
    second = client.post(
        "/portal/training/challenges/WEB-001/start", headers=headers()
    ).json()
    assert first["started_at"] == second["started_at"]
    attempt(ts=first["started_at"] + 60, passed=True)
    attempt(ts=first["started_at"] + 90, passed=True)
    result = client.get("/portal/training/me", headers=headers()).json()
    assert result["activity"][0]["elapsed_sec"] == 60
    assert portal._SOLVES == {}


def test_starting_after_a_historical_pass_does_not_invent_negative_duration(client):
    attempt(passed=True)
    client.post("/portal/training/challenges/WEB-001/start", headers=headers())
    result = client.get("/portal/training/me", headers=headers()).json()
    assert result["activity"][0]["elapsed_sec"] is None


def test_real_submit_attributes_verified_actor_and_cannot_override_grader_team(
    client, monkeypatch
):
    seen = []

    def grade(submission, context):
        seen.append(submission)
        return SimpleNamespace(
            passed=True, points=30, detail="Verified training evidence"
        )

    monkeypatch.setattr(
        portal, "_load_module", lambda *args: SimpleNamespace(grade_red=grade)
    )
    body = {
        "team_id": "alpha",
        "match_id": "exercise-one",
        "subject": "impersonated",
        "fields": {"team_id": "victim", "flag": "isolated-test-answer"},
    }
    response = client.post(
        "/portal/challenges/WEB-001/submit", headers=headers(), json=body
    )
    assert response.status_code == 200 and response.json()["passed"]
    assert seen[0]["team_id"] == "exercise-one::alpha"
    result = client.get("/portal/training/me", headers=headers()).json()
    assert result["activity"][0]["attempts"] == 1
    assert portal._SOLVES["exercise-one::alpha"]["WEB-001"]["by"] == "learner-one"
    assert "isolated-test-answer" not in json.dumps(result)
    assert "impersonated" not in json.dumps(result)


def test_revoked_session_never_reads_personal_evidence(client, monkeypatch):
    async def revoked(_):
        raise HTTPException(401, "Session revoked")

    monkeypatch.setattr(scope, "verify_session", revoked)
    assert client.get("/portal/training/me", headers=headers()).status_code == 401


def test_recommendations_are_transparent_and_preserve_unknown_domains(client):
    attempt(passed=False, cid="ICS-001")
    conn = portal._ac_db()
    try:
        result = training.profile(
            conn,
            Identity(
                actor="learner-one",
                role="red",
                team_id="alpha",
                match_id="exercise-one",
            ),
            CATALOG,
        )
    finally:
        conn.close()
    assert result["recommendations"][0]["id"] == "ICS-001"
    assert "Continue a recorded attempt" == result["recommendations"][0]["reason"]
    assert (
        next(d for d in result["domains"] if d["domain"] == "Incident Response")[
            "proficiency"
        ]
        is None
    )
