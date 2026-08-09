from __future__ import annotations

import time

import jwt
import pytest
from fastapi.testclient import TestClient

from services.attack_defense.api import create_app
from services.attack_defense.mode_strategies import supported_score_categories
from services.attack_defense.utils import json_load

from .conftest import bootstrap


JWT_SECRET = "koth-test-jwt-secret-with-enough-entropy"


def _token(role: str, team_id: str = "", match_id: str = "match-1") -> str:
    return jwt.encode(
        {
            "sub": f"{role}-{team_id or 'operator'}",
            "role": role,
            "team_id": team_id,
            "match_id": match_id,
            "type": "access",
            "exp": int(time.time()) + 300,
        },
        JWT_SECRET,
        algorithm="HS256",
    )


def _enable(ad, *, lease_rounds: int = 2, points: int = 3):
    return ad.koth.configure(
        "match-1",
        enabled=True,
        service_ids=["service-vulnerable-notes"],
        lease_rounds=lease_rounds,
        points_per_round=points,
        score_weight=1.0,
        actor="operator",
        reason="enable KOTH test policy",
    )


def _victim_flag(ad, victim_team: str = "team-2") -> str:
    current = ad.repo.current_round("match-1")
    conn = ad.db.connect()
    try:
        row = dict(conn.execute(
            """SELECT * FROM flags WHERE round_id=? AND team_id=?
               AND service_id='service-vulnerable-notes'""",
            (current["id"], victim_team),
        ).fetchone())
    finally:
        conn.close()
    return ad.flags.reconstruct(row)


def test_koth_is_optional_policy_not_a_fourth_match_mode(ad):
    bootstrap(ad, teams=2, services=1)
    match = ad.repo.get_match("match-1")
    config = json_load(match["config"])
    assert config["koth"]["enabled"] is False
    assert "koth" not in config["score_categories"]
    assert "koth" in supported_score_categories("attack_defense")
    assert "koth" in supported_score_categories("hybrid_live_fire")
    assert "koth" not in supported_score_categories("exercise")
    with pytest.raises(ValueError, match="score_categories"):
        ad.repo.create_match(
            "Invalid exercise KOTH", 5, 3,
            {"koth": {"enabled": True}}, "exercise-koth", "exercise",
        )


def test_match_creation_keeps_koth_category_with_explicit_categories(ad):
    match = ad.repo.create_match(
        "Configured KOTH",
        5,
        3,
        {
            "score_categories": ["attack", "defense", "availability"],
            "koth": {
                "enabled": True,
                "service_ids": [],
                "lease_rounds": 2,
                "points_per_round": 3,
                "score_weight": 2,
            },
        },
        "configured-koth",
        "attack_defense",
    )
    config = json_load(match["config"])
    assert config["score_categories"] == [
        "attack", "defense", "availability", "koth"
    ]
    assert config["score_weights"]["koth"] == 2.0


def test_valid_flag_atomically_acquires_hill_and_scores_functional_control(ad):
    bootstrap(ad, teams=3, services=1)
    configured = _enable(ad, lease_rounds=2, points=3)
    assert configured["enabled"] is True
    assert len(configured["hills"]) == 3

    ad.engine.start_match("match-1", "operator")
    result = ad.flags.validate_submission(
        "match-1", "team-1", _victim_flag(ad), "team-one"
    )
    assert result.accepted and result.score_delta == 10

    state = ad.koth.state("match-1", operator=False)
    owned = next(
        hill for hill in state["hills"]
        if hill["victim_team_id"] == "team-2"
    )
    assert owned["status"] == "owned"
    assert owned["owner_team_id"] == "team-1"
    assert owned["remaining_rounds"] == 2
    assert "source_flag_id" not in str(state)

    ad.engine.force_finalize("match-1", "operator")
    board = ad.scoring.scoreboard("match-1", public=False)
    team_one = next(row for row in board if row["team_id"] == "team-1")
    assert team_one["attack"] == 10
    assert team_one["koth"] == 3
    assert team_one["total"] >= 13

    conn = ad.db.connect()
    try:
        assert conn.execute("SELECT COUNT(*) FROM koth_leases").fetchone()[0] == 1
        assert conn.execute(
            "SELECT COUNT(*) FROM score_ledger WHERE score_type='koth' AND delta=3"
        ).fetchone()[0] == 1
    finally:
        conn.close()


def test_latest_valid_capture_transfers_hill_and_duplicate_does_not_renew(ad):
    bootstrap(ad, teams=3, services=1)
    _enable(ad)
    ad.engine.start_match("match-1", "operator")
    flag = _victim_flag(ad)

    first = ad.flags.validate_submission("match-1", "team-1", flag, "team-one")
    duplicate = ad.flags.validate_submission("match-1", "team-1", flag, "team-one")
    transfer = ad.flags.validate_submission("match-1", "team-3", flag, "team-three")
    assert first.accepted and not duplicate.accepted and transfer.accepted

    state = ad.koth.state("match-1", operator=True)
    hill = next(item for item in state["hills"] if item["victim_team_id"] == "team-2")
    assert hill["owner_team_id"] == "team-3"
    conn = ad.db.connect()
    try:
        leases = conn.execute(
            "SELECT owner_team_id FROM koth_leases ORDER BY sequence"
        ).fetchall()
        results = conn.execute(
            """SELECT result FROM audit_events WHERE event_type='koth_ownership'
               ORDER BY timestamp"""
        ).fetchall()
    finally:
        conn.close()
    assert [row[0] for row in leases] == ["team-1", "team-3"]
    assert [row[0] for row in results] == ["acquired", "captured"]


def test_lease_scores_for_configured_rounds_then_expires(ad):
    bootstrap(ad, teams=3, services=1)
    _enable(ad, lease_rounds=2, points=4)
    ad.engine.start_match("match-1", "operator")
    ad.flags.validate_submission(
        "match-1", "team-1", _victim_flag(ad), "team-one"
    )

    ad.engine.force_finalize("match-1", "operator")
    assert ad.engine.tick_match("match-1")["round"] == 2
    ad.engine.force_finalize("match-1", "operator")
    assert ad.engine.tick_match("match-1")["round"] == 3

    state = ad.koth.state("match-1")
    hill = next(item for item in state["hills"] if item["victim_team_id"] == "team-2")
    assert hill["status"] == "unclaimed"
    ad.engine.force_finalize("match-1", "operator")

    team_one = next(
        row for row in ad.scoring.scoreboard("match-1", public=False)
        if row["team_id"] == "team-1"
    )
    assert team_one["koth"] == 8
    before = team_one
    ad.scoring.recalculate_match("match-1", "operator")
    after = next(
        row for row in ad.scoring.scoreboard("match-1", public=False)
        if row["team_id"] == "team-1"
    )
    assert before == after


def test_nonfunctional_hill_receives_no_koth_score(ad):
    bootstrap(ad, teams=3, services=1)
    _enable(ad, lease_rounds=1, points=9)
    ad.engine.start_match("match-1", "operator")
    current = ad.repo.current_round("match-1")
    ad.flags.validate_submission(
        "match-1", "team-1", _victim_flag(ad), "team-one"
    )
    with ad.db.transaction(immediate=True) as conn:
        conn.execute(
            """UPDATE service_checks SET status='failed',error_code='workflow_failed'
               WHERE round_id=? AND team_id='team-2'
               AND service_id='service-vulnerable-notes'
               AND check_type='benign_workflow'""",
            (current["id"],),
        )
    ad.engine.force_finalize("match-1", "operator")
    team_one = next(
        row for row in ad.scoring.scoreboard("match-1", public=False)
        if row["team_id"] == "team-1"
    )
    assert team_one["koth"] == 0


def test_koth_operator_authorization_and_public_redaction(ad, monkeypatch):
    bootstrap(ad, teams=3, services=1)
    monkeypatch.setenv("AUTH_JWT_SECRET", JWT_SECRET)
    client = TestClient(create_app(ad))
    competitor = {
        "Authorization": f"Bearer {_token('competitor', 'team-1')}"
    }
    operator = {"Authorization": f"Bearer {_token('operator')}"}
    path = "/api/attack-defense/operator/matches/match-1/koth/configure"
    body = {
        "enabled": True,
        "service_ids": ["service-vulnerable-notes"],
        "lease_rounds": 2,
        "points_per_round": 3,
        "score_weight": 1,
        "reason": "enable KOTH for API test",
    }
    assert client.post(path, headers=competitor, json=body).status_code == 403
    configured = client.post(path, headers=operator, json=body)
    assert configured.status_code == 200

    public = client.get("/api/attack-defense/matches/match-1/koth")
    assert public.status_code == 200
    assert public.json()["disclosure"] == "ownership-only-no-flag-or-endpoint"
    assert "source_flag" not in public.text
    assert "token" not in public.text
    assert all("endpoint" not in hill for hill in public.json()["hills"])
    assert "acquired_at" not in public.text

    ad.engine.start_match("match-1", "operator")
    blocked = client.post(path, headers=operator, json={
        **body, "reason": "unsafe live reconfiguration",
    })
    assert blocked.status_code == 409


def test_koth_configuration_rejects_cross_match_service(ad):
    bootstrap(ad, teams=2, services=1)
    with pytest.raises(ValueError, match="belong"):
        ad.koth.configure(
            "match-1",
            enabled=True,
            service_ids=["service-from-other-match"],
            lease_rounds=2,
            points_per_round=3,
            score_weight=1,
            actor="operator",
            reason="invalid cross match service",
        )


def test_reconfiguration_epoch_does_not_reactivate_old_lease(ad):
    bootstrap(ad, teams=3, services=1)
    _enable(ad, lease_rounds=3)
    ad.engine.start_match("match-1", "operator")
    accepted = ad.flags.validate_submission(
        "match-1", "team-1", _victim_flag(ad), "team-one"
    )
    assert accepted.accepted

    ad.engine.pause_match("match-1", "operator", "reconfigure KOTH policy")
    ad.koth.configure(
        "match-1",
        enabled=False,
        service_ids=["service-vulnerable-notes"],
        lease_rounds=3,
        points_per_round=3,
        score_weight=1.0,
        actor="operator",
        reason="rotate ownership epoch",
    )
    reenabled = _enable(ad, lease_rounds=3)

    hill = next(
        item for item in reenabled["hills"]
        if item["victim_team_id"] == "team-2"
    )
    assert hill["status"] == "unclaimed"
    assert hill["owner_team_id"] is None
    conn = ad.db.connect()
    try:
        assert conn.execute("SELECT COUNT(*) FROM koth_leases").fetchone()[0] == 1
    finally:
        conn.close()
