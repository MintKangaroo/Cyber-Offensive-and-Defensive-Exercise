from __future__ import annotations

import hashlib
import time

import jwt
import pytest
from fastapi.testclient import TestClient

from services.attack_defense.api import _public_event, create_app
from services.attack_defense.mode_strategies import supported_score_categories
from services.attack_defense.utils import canonical_json, json_load
from shared.rbac import Identity

from .conftest import bootstrap


JWT_SECRET = "stealth-test-jwt-secret-with-enough-entropy"


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


def _enable(ad, *, delay: int = 2, window: int = 1, points: int = 4):
    return ad.stealth.configure(
        "match-1",
        enabled=True,
        alert_delay_rounds=delay,
        detection_window_rounds=window,
        attacker_undetected_points=points,
        defender_detection_points=points + 1,
        attack_score_weight=1.0,
        detection_score_weight=1.0,
        actor="operator",
        reason="enable Stealth test policy",
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


def test_stealth_is_optional_policy_and_never_exercise_mode(ad):
    bootstrap(ad, teams=2, services=1)
    config = json_load(ad.repo.get_match("match-1")["config"])
    assert config["stealth"]["enabled"] is False
    assert "stealth_attack" in supported_score_categories("attack_defense")
    assert "stealth_detection" in supported_score_categories("hybrid_live_fire")
    assert "stealth_attack" not in supported_score_categories("exercise")
    with pytest.raises(ValueError, match="score_categories"):
        ad.repo.create_match(
            "Invalid Stealth exercise",
            5,
            3,
            {"stealth": {"enabled": True}},
            "exercise-stealth",
            "exercise",
        )


def test_accepted_flag_creates_withheld_incident_without_changing_response(ad):
    bootstrap(ad, teams=3, services=1)
    _enable(ad)
    ad.engine.start_match("match-1", "operator")
    result = ad.flags.validate_submission(
        "match-1", "team-1", _victim_flag(ad), "team-one"
    )
    assert result.accepted and result.score_delta == 10

    victim = ad.stealth.state("match-1", team_id="team-2")
    operator = ad.stealth.state("match-1", operator=True)
    observer = ad.stealth.state("match-1", observer=True)
    assert victim["incidents"] == []
    assert observer["incidents"] == []
    assert len(operator["incidents"]) == 1
    assert operator["incidents"][0]["attacker_team_id"] == "team-1"


def test_pre_disclosure_detection_scores_defender_and_never_returns_match_oracle(ad):
    bootstrap(ad, teams=3, services=1)
    _enable(ad, window=1, points=4)
    ad.engine.start_match("match-1", "operator")
    ad.flags.validate_submission(
        "match-1", "team-1", _victim_flag(ad), "team-one"
    )
    response = ad.stealth.report_detection(
        "match-1",
        "team-2",
        "service-vulnerable-notes",
        hashlib.sha256(b"siem-evidence").hexdigest(),
        "Correlated application anomaly and EDR signal",
        "detection-report-001",
        "team-two",
    )
    assert response["recorded"] is True
    assert response["status"] == "pending_verification"
    assert "matched" not in str(response)

    ad.engine.force_finalize("match-1", "operator")
    board = ad.scoring.scoreboard("match-1", public=False)
    defender = next(row for row in board if row["team_id"] == "team-2")
    attacker = next(row for row in board if row["team_id"] == "team-1")
    assert defender["stealth_detection"] == 5
    assert attacker["stealth_attack"] == 0

    before = defender
    ad.scoring.recalculate_match("match-1", "operator")
    after = next(
        row for row in ad.scoring.scoreboard("match-1", public=False)
        if row["team_id"] == "team-2"
    )
    assert before == after


def test_undetected_incident_scores_attacker_and_alert_releases_later(ad):
    bootstrap(ad, teams=3, services=1)
    _enable(ad, delay=2, window=1, points=6)
    ad.engine.start_match("match-1", "operator")
    ad.flags.validate_submission(
        "match-1", "team-1", _victim_flag(ad), "team-one"
    )
    ad.engine.force_finalize("match-1", "operator")
    attacker = next(
        row for row in ad.scoring.scoreboard("match-1", public=False)
        if row["team_id"] == "team-1"
    )
    assert attacker["stealth_attack"] == 6
    assert ad.stealth.state("match-1", team_id="team-2")["incidents"] == []

    assert ad.engine.tick_match("match-1")["round"] == 2
    assert ad.stealth.state("match-1", team_id="team-2")["incidents"] == []
    ad.engine.force_finalize("match-1", "operator")
    assert ad.engine.tick_match("match-1")["round"] == 3
    released = ad.stealth.state("match-1", team_id="team-2")["incidents"]
    assert len(released) == 1
    assert released[0]["status"] == "undetected"
    assert "attacker" not in str(released)


def test_detection_report_is_idempotent_and_cross_team_service_is_rejected(ad):
    bootstrap(ad, teams=3, services=1)
    _enable(ad)
    ad.engine.start_match("match-1", "operator")
    kwargs = dict(
        match_id="match-1",
        team_id="team-2",
        service_id="service-vulnerable-notes",
        indicator_hash=hashlib.sha256(b"evidence").hexdigest(),
        evidence_summary="Independent SIEM correlation evidence",
        idempotency_key="same-report-key",
        actor="team-two",
    )
    first = ad.stealth.report_detection(**kwargs)
    second = ad.stealth.report_detection(**kwargs)
    assert first == second
    conn = ad.db.connect()
    try:
        assert conn.execute(
            "SELECT COUNT(*) FROM stealth_detection_reports"
        ).fetchone()[0] == 1
    finally:
        conn.close()
    with pytest.raises(ValueError, match="service does not belong"):
        ad.stealth.report_detection(
            **{**kwargs, "service_id": "other-match-service",
               "idempotency_key": "invalid-service"}
        )


def test_stealth_api_authorization_delay_and_scoreboard_floor(ad, monkeypatch):
    bootstrap(ad, teams=3, services=1)
    monkeypatch.setenv("AUTH_JWT_SECRET", JWT_SECRET)
    client = TestClient(create_app(ad))
    operator = {"Authorization": f"Bearer {_token('operator')}"}
    team_two = {"Authorization": f"Bearer {_token('competitor', 'team-2')}"}
    team_one = {"Authorization": f"Bearer {_token('competitor', 'team-1')}"}
    path = "/api/attack-defense/operator/matches/match-1/stealth/configure"
    body = {
        "enabled": True,
        "alert_delay_rounds": 2,
        "detection_window_rounds": 1,
        "attacker_undetected_points": 4,
        "defender_detection_points": 5,
        "attack_score_weight": 1,
        "detection_score_weight": 1,
        "reason": "enable API Stealth policy",
    }
    assert client.post(path, headers=team_one, json=body).status_code == 403
    assert client.post(path, headers=operator, json=body).status_code == 200
    ad.engine.start_match("match-1", "operator")
    blocked = client.post(
        path, headers=operator,
        json={**body, "reason": "unsafe live Stealth reconfiguration"},
    )
    assert blocked.status_code == 409

    flag_response = client.post(
        "/api/attack-defense/matches/match-1/flags/submit",
        headers=team_one,
        json={"flag": _victim_flag(ad)},
    )
    assert flag_response.status_code == 200
    assert flag_response.json() == {
        "accepted": True, "status": "accepted", "score_delta": 10,
    }

    no_key = client.post(
        "/api/attack-defense/matches/match-1/stealth/detections",
        headers=team_two,
        json={
            "service_id": "service-vulnerable-notes",
            "indicator_hash": hashlib.sha256(b"api").hexdigest(),
            "evidence_summary": "SIEM and EDR correlation evidence",
        },
    )
    assert no_key.status_code == 400
    recorded = client.post(
        "/api/attack-defense/matches/match-1/stealth/detections",
        headers={**team_two, "Idempotency-Key": "api-report-001"},
        json={
            "service_id": "service-vulnerable-notes",
            "indicator_hash": hashlib.sha256(b"api").hexdigest(),
            "evidence_summary": "SIEM and EDR correlation evidence",
        },
    )
    assert recorded.status_code == 202
    assert recorded.json()["status"] == "pending_verification"
    assert "matched" not in recorded.text

    own = client.get(
        "/api/attack-defense/matches/match-1/stealth", headers=team_two
    )
    assert own.status_code == 200
    assert "internal_result" not in own.text
    assert "attacker_team" not in own.text
    assert client.get(
        "/api/attack-defense/matches/match-1/stealth", headers=team_one
    ).status_code == 200
    board = client.get("/api/attack-defense/matches/match-1/scoreboard")
    assert board.json()["delay_rounds"] == 2
    metrics = client.get("/metrics").text
    assert "attack_defense_stealth_incident_total 1" in metrics
    assert "attack_defense_stealth_detection_report_total 1" in metrics
    assert "attack_defense_stealth_detected_total 1" in metrics


def test_stealth_and_koth_public_ownership_share_disclosure_delay(ad):
    bootstrap(ad, teams=3, services=1)
    _enable(ad, delay=2, window=1)
    ad.koth.configure(
        "match-1",
        enabled=True,
        service_ids=["service-vulnerable-notes"],
        lease_rounds=3,
        points_per_round=2,
        score_weight=1,
        actor="operator",
        reason="combine KOTH with delayed disclosure",
    )
    ad.engine.start_match("match-1", "operator")
    ad.flags.validate_submission(
        "match-1", "team-1", _victim_flag(ad), "team-one"
    )
    operator = ad.koth.state("match-1", operator=True)
    public = ad.koth.state("match-1", operator=False)
    assert any(hill["status"] == "owned" for hill in operator["hills"])
    assert all(hill["status"] == "unclaimed" for hill in public["hills"])
    assert public["as_of_round"] == 0
    assert public["disclosure"].startswith("delayed-")


def test_sensitive_stealth_and_koth_sse_events_are_not_public_oracles():
    base = {
        "event_id": "event-1",
        "result": "withheld",
        "timestamp": 100.0,
        "team_id": "team-2",
        "round_id": "round-1",
        "service_id": "service-1",
        "metadata": canonical_json({"attacker_team_id": "team-1"}),
        "match_config": canonical_json({
            "stealth": {"enabled": True, "alert_delay_rounds": 2}
        }),
    }
    competitor = Identity(
        actor="team-two", role="competitor", team_id="team-2", match_id="match-1"
    )
    assert _public_event(
        {**base, "event_type": "stealth_incident"}, competitor
    ) is None
    assert _public_event(
        {**base, "event_type": "koth_ownership"}, competitor
    ) is None
    operator = Identity(actor="referee", role="operator")
    internal = _public_event(
        {**base, "event_type": "stealth_incident"}, operator
    )
    assert internal and internal["metadata"]["attacker_team_id"] == "team-1"
