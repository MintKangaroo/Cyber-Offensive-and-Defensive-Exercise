"""Instructor-reviewed defensive rubrics (roadmap priority 3, part B).

A Blue challenge may carry a rubric; an instructor scores a learner's defensive
work against it. The review is recorded per learner and surfaced in the personal
training profile — never touching competition scores.
"""
import time

import jwt
import pytest
import yaml
from fastapi.testclient import TestClient

from services.challenge_portal import anticheat
from services.challenge_portal import main as portal
from shared import scope

SECRET = "blue-reviews-test-key-not-for-production-32-bytes-x"  # training-only fixture


def headers(actor="blue-learner", team="bteam", match="exercise-one", role="blue"):
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

    cdir = tmp_path / "detection" / "DET-RUBRIC"
    cdir.mkdir(parents=True)
    (cdir / "challenge.yaml").write_text(yaml.safe_dump({
        "challenge": {
            "id": "DET-RUBRIC", "title": "Reviewed detection", "category": "detection",
            "difficulty": "medium",
            "blue_task": {"goal": "detect", "success_criteria": "x", "rubric": [
                {"criterion": "detection coverage", "max": 10},
                {"criterion": "false-positive control", "max": 5},
            ]},
        }
    }))
    monkeypatch.setattr(portal, "CATALOG", {})
    monkeypatch.setattr(portal, "BLUE_CATALOG", {
        "DET-RUBRIC": {"id": "DET-RUBRIC", "title": "Reviewed detection",
                       "category": "detection", "difficulty": "medium", "dir": str(cdir)},
        "DET-PLAIN": {"id": "DET-PLAIN", "title": "No rubric", "category": "detection",
                      "difficulty": "easy", "dir": str(tmp_path)},  # dir without matching yaml
    })

    conn = portal._ac_db()
    anticheat.init_audit(conn)
    conn.close()

    async def verified(_):
        pass
    monkeypatch.setattr(scope, "verify_session", verified)
    return TestClient(portal.app)


def _blue_pass(subject="blue-learner", team="bteam", match="exercise-one", cid="DET-RUBRIC"):
    conn = portal._ac_db()
    try:
        anticheat.record(
            anticheat.AntiCheatState(), conn, team, match, cid, "blue",
            "opaque-hash", True, time.time(), anticheat.Config(), verified_subject=subject,
        )
    finally:
        conn.close()


def test_rubric_is_readable_by_member_and_instructor(client):
    for h in (headers(), headers(actor="range-instructor", role="instructor")):
        r = client.get("/portal/training/blue/DET-RUBRIC/rubric", headers=h)
        assert r.status_code == 200
        assert [c["criterion"] for c in r.json()["rubric"]] == [
            "detection coverage", "false-positive control"]


def test_review_requires_instructor(client):
    r = client.post("/portal/training/blue/DET-RUBRIC/review", headers=headers(),
                    json={"subject": "blue-learner", "team_id": "bteam", "match_id": "exercise-one",
                          "scores": {"detection coverage": 8}})
    assert r.status_code == 403


def test_review_scores_clamp_and_record(client):
    r = client.post("/portal/training/blue/DET-RUBRIC/review", headers=headers(actor="range-instructor", role="instructor"),
                    json={"subject": "blue-learner", "team_id": "bteam", "match_id": "exercise-one",
                          "scores": {"detection coverage": 99, "false-positive control": 4},
                          "feedback": "tighten the rule"})
    assert r.status_code == 200
    body = r.json()
    assert body["score"] == 14 and body["max"] == 15  # 10 (clamped) + 4
    assert body["pct"] == 93
    assert body["reviewed_by"] == "range-instructor"


def test_review_rejected_without_a_rubric(client):
    r = client.post("/portal/training/blue/DET-PLAIN/review", headers=headers(actor="range-instructor", role="instructor"),
                    json={"subject": "blue-learner", "team_id": "bteam", "match_id": "exercise-one",
                          "scores": {}})
    assert r.status_code == 400


def test_review_surfaces_in_personal_profile_without_touching_scores(client):
    client.post("/portal/training/blue/DET-RUBRIC/review", headers=headers(actor="range-instructor", role="instructor"),
                json={"subject": "blue-learner", "team_id": "bteam", "match_id": "exercise-one",
                      "scores": {"detection coverage": 9, "false-positive control": 5},
                      "feedback": "solid"})
    me = client.get("/portal/training/me", headers=headers()).json()
    entry = next(a for a in me["activity"] if a["id"] == "DET-RUBRIC")
    assert entry["review"]["score"] == 14 and entry["review"]["max"] == 15
    assert entry["review"]["feedback"] == "solid"
    assert entry["review"]["reviewed_by"] == "range-instructor"
    # competition scoreboards untouched
    assert portal._SOLVES == {} and portal._BLUE_SOLVES == {}


def test_pending_queue_lists_unreviewed_blue_passes(client):
    _blue_pass()  # a passed blue submission with a rubric, not yet reviewed
    pending = client.get("/portal/training/blue/reviews/pending", headers=headers(actor="range-instructor", role="instructor")).json()
    assert pending["count"] == 1
    assert pending["pending"][0]["subject"] == "blue-learner"
    assert pending["pending"][0]["cid"] == "DET-RUBRIC"
    # after review it disappears from the queue
    client.post("/portal/training/blue/DET-RUBRIC/review", headers=headers(actor="range-instructor", role="instructor"),
                json={"subject": "blue-learner", "team_id": "bteam", "match_id": "exercise-one",
                      "scores": {"detection coverage": 10, "false-positive control": 5}})
    after = client.get("/portal/training/blue/reviews/pending", headers=headers(actor="range-instructor", role="instructor")).json()
    assert after["count"] == 0


def test_pending_queue_requires_instructor(client):
    assert client.get("/portal/training/blue/reviews/pending", headers=headers()).status_code == 403
