from __future__ import annotations

import time

import jwt
import pytest
from fastapi.testclient import TestClient

from services.attack_defense.api import create_app
from services.attack_defense.metrics import render_metrics
from services.attack_defense.tournament import seed_order

JWT_SECRET = "tournament-test-jwt-secret-with-enough-entropy"


def _token(
    role: str,
    *,
    subject: str,
    tournament_id: str = "",
    match_id: str = "",
    team_id: str = "",
) -> str:
    return jwt.encode(
        {
            "sub": subject,
            "role": role,
            "tournament_id": tournament_id,
            "match_id": match_id,
            "team_id": team_id,
            "type": "access",
            "exp": int(time.time()) + 300,
        },
        JWT_SECRET,
        algorithm="HS256",
    )


def _create_tournament(ad, size: int = 4) -> dict:
    tournament = ad.tournaments.create(
        name="LiveCTF Test",
        bracket_size=size,
        match_mode="attack_defense",
        round_duration_seconds=5,
        active_flag_window=3,
        match_config={},
        actor="operator",
        tournament_id="tournament-1",
    )
    for index in range(1, size + 1):
        ad.tournaments.add_entry(
            tournament["id"],
            slug=f"team-{index:02}",
            name=f"Team {index}",
            identity_subject=f"captain-{index}",
            seed=index,
            actor="operator",
            entry_id=f"entry-{index}",
        )
    ad.tournaments.add_service(
        tournament["id"],
        slug="vulnerable-notes",
        name="Vulnerable Notes",
        base_image="registry.local/base/vulnerable-notes:v1",
        internal_port=9000,
        checker_type="vulnerable_notes",
        config={
            "endpoint_template": "http://{team_slug}-{service_slug}:9000",
            "management_endpoint_template": (
                "http://{team_slug}-{service_slug}:9001"
            ),
        },
        actor="operator",
        service_id="tournament-service-notes",
    )
    return ad.tournaments.seed(
        tournament["id"], "operator", "lock deterministic bracket"
    )


def _finish_fixture(ad, fixture: dict, winner_entry_id: str) -> dict:
    ad.engine.start_match(fixture["match_id"], "operator")
    ad.tournaments.mark_fixture_running(
        fixture["id"], "operator", "begin scheduled fixture"
    )
    mapping = next(
        item
        for item in ad.tournaments.fixture(fixture["id"], operator=True)[
            "match_teams"
        ]
        if item["entry_id"] == winner_entry_id
    )
    ad.scoring.adjustment(
        fixture["match_id"],
        mapping["match_team_id"],
        1,
        "deterministic tournament test winner",
        "operator",
    )
    ad.engine.end_match(fixture["match_id"], "operator", "fixture complete")
    return ad.tournaments.finalize_fixture(
        fixture["id"], "operator", "advance scoreboard winner"
    )


def test_seed_order_and_tournament_validation(ad):
    assert seed_order(2) == [1, 2]
    assert seed_order(4) == [1, 4, 2, 3]
    assert seed_order(8) == [1, 8, 4, 5, 2, 7, 3, 6]
    with pytest.raises(ValueError, match="bracket_size"):
        seed_order(3)
    with pytest.raises(ValueError, match="symmetric"):
        ad.tournaments.create(
            name="Invalid",
            bracket_size=2,
            match_mode="exercise",
            round_duration_seconds=5,
            active_flag_window=3,
            match_config={},
            actor="operator",
        )


def test_single_elimination_materializes_isolated_matches_and_champion(ad):
    seeded = _create_tournament(ad)
    assert seeded["status"] == "seeded"
    first_stage = [
        item for item in seeded["fixtures"] if item["stage_sequence"] == 1
    ]
    assert len(first_stage) == 2
    assert [
        (item["team_a_entry_id"], item["team_b_entry_id"])
        for item in first_stage
    ] == [("entry-1", "entry-4"), ("entry-2", "entry-3")]
    assert all(item["status"] == "scheduled" for item in first_stage)
    assert all(item["match_id"] for item in first_stage)
    assert ad.tournaments.reconcile("tournament-1", "operator")["materialized"] == 0

    ad.tournaments.start("tournament-1", "operator", "open LiveCTF play")
    _finish_fixture(ad, first_stage[0], "entry-1")
    _finish_fixture(ad, first_stage[1], "entry-2")

    state = ad.tournaments.state("tournament-1", operator=True)
    final = next(item for item in state["fixtures"] if item["stage_sequence"] == 2)
    assert final["status"] == "scheduled"
    assert (final["team_a_entry_id"], final["team_b_entry_id"]) == (
        "entry-1",
        "entry-2",
    )

    semifinal_team_id = next(
        item["match_team_id"]
        for item in ad.tournaments.fixture(first_stage[0]["id"], operator=True)[
            "match_teams"
        ]
        if item["entry_id"] == "entry-1"
    )
    final_team_id = next(
        item["match_team_id"]
        for item in ad.tournaments.fixture(final["id"], operator=True)["match_teams"]
        if item["entry_id"] == "entry-1"
    )
    assert semifinal_team_id != final_team_id

    finalized = _finish_fixture(ad, final, "entry-1")
    assert finalized["winner_entry_id"] == "entry-1"
    completed = ad.tournaments.state("tournament-1", operator=True)
    assert completed["status"] == "completed"
    assert completed["winner_entry_id"] == "entry-1"
    assert ad.tournaments.entry("entry-1", operator=True)["status"] == "champion"
    assert ad.tournaments.finalize_fixture(
        final["id"], "operator", "idempotent retry"
    )["winner_entry_id"] == "entry-1"

    metrics = render_metrics(ad.db)
    assert "attack_defense_tournament_total 1" in metrics
    assert "attack_defense_tournament_fixture_total 3" in metrics
    assert "attack_defense_tournament_fixture_finalized_total 3" in metrics


def test_tied_fixture_requires_explicit_winner(ad):
    seeded = _create_tournament(ad, size=2)
    fixture = seeded["fixtures"][0]
    ad.tournaments.start("tournament-1", "operator", "open tied fixture")
    ad.engine.start_match(fixture["match_id"], "operator")
    ad.tournaments.mark_fixture_running(
        fixture["id"], "operator", "begin tied fixture"
    )
    ad.engine.end_match(fixture["match_id"], "operator", "fixture complete")
    with pytest.raises(ValueError, match="explicit winner"):
        ad.tournaments.finalize_fixture(
            fixture["id"], "operator", "attempt automatic tie resolution"
        )
    result = ad.tournaments.finalize_fixture(
        fixture["id"],
        "operator",
        "referee tie-break decision",
        winner_entry_id="entry-2",
    )
    assert result["winner_entry_id"] == "entry-2"


def test_startup_recovers_ready_unmaterialized_fixture(ad):
    seeded = _create_tournament(ad)
    final = next(
        item for item in seeded["fixtures"] if item["stage_sequence"] == 2
    )
    with ad.db.transaction(immediate=True) as conn:
        conn.execute(
            """UPDATE tournament_fixtures
               SET team_a_entry_id='entry-1',team_b_entry_id='entry-2',
                   status='pending',match_id=NULL WHERE id=?""",
            (final["id"],),
        )
    with TestClient(create_app(ad)) as client:
        assert client.get("/health").status_code == 200
    recovered = ad.tournaments.fixture(final["id"], operator=True)
    assert recovered["status"] == "scheduled"
    assert recovered["match_id"]
    assert len(recovered["match_teams"]) == 2


def test_tournament_api_authorization_identity_and_public_redaction(ad, monkeypatch):
    seeded = _create_tournament(ad, size=2)
    monkeypatch.setenv("AUTH_JWT_SECRET", JWT_SECRET)
    client = TestClient(create_app(ad))
    operator = {
        "Authorization": f"Bearer {_token('operator', subject='operator')}"
    }
    participant = {
        "Authorization": (
            "Bearer "
            + _token(
                "competitor",
                subject="captain-1",
                tournament_id="tournament-1",
            )
        )
    }
    outsider = {
        "Authorization": (
            "Bearer "
            + _token(
                "competitor",
                subject="not-registered",
                tournament_id="tournament-1",
            )
        )
    }

    assert client.get(
        "/api/attack-defense/operator/tournaments", headers=participant
    ).status_code == 403
    operator_state = client.get(
        "/api/attack-defense/operator/tournaments/tournament-1", headers=operator
    )
    assert operator_state.status_code == 200
    assert "identity_subject" in operator_state.text

    own = client.get(
        "/api/attack-defense/tournaments/tournament-1", headers=participant
    )
    assert own.status_code == 200
    assert own.json()["identity"]["entry_id"] == "entry-1"
    assert own.json()["identity"]["credential_scope"] == (
        "fresh-match-token-required-per-fixture"
    )
    assert client.get(
        "/api/attack-defense/tournaments/tournament-1", headers=outsider
    ).status_code == 403

    public = client.get("/api/attack-defense/public/tournaments/tournament-1")
    assert public.status_code == 200
    assert public.json()["config"] == {}
    assert "identity_subject" not in public.text
    assert "match_teams" not in public.text
    assert "reason" not in public.text
    assert "match_id" not in public.json()["fixtures"][0]
    assert seeded["fixtures"][0]["match_id"]


def test_operator_api_drives_complete_two_team_fixture(ad, monkeypatch):
    monkeypatch.setenv("AUTH_JWT_SECRET", JWT_SECRET)
    client = TestClient(create_app(ad))
    headers = {
        "Authorization": f"Bearer {_token('operator', subject='referee')}"
    }
    created = client.post(
        "/api/attack-defense/operator/tournaments",
        headers=headers,
        json={
            "id": "api-cup",
            "name": "API Cup",
            "bracket_size": 2,
            "match_mode": "attack_defense",
        },
    )
    assert created.status_code == 201
    for index in (1, 2):
        response = client.post(
            "/api/attack-defense/operator/tournaments/api-cup/entries",
            headers=headers,
            json={
                "id": f"api-entry-{index}",
                "slug": f"api-team-{index}",
                "name": f"API Team {index}",
                "identity_subject": f"api-captain-{index}",
                "seed": index,
            },
        )
        assert response.status_code == 201
    service = client.post(
        "/api/attack-defense/operator/tournaments/api-cup/services",
        headers=headers,
        json={
            "id": "api-notes",
            "slug": "vulnerable-notes",
            "name": "Vulnerable Notes",
            "base_image": "registry.local/base/vulnerable-notes:v1",
            "internal_port": 9000,
            "checker_type": "vulnerable_notes",
            "config": {},
        },
    )
    assert service.status_code == 201
    seeded = client.post(
        "/api/attack-defense/operator/tournaments/api-cup/seed",
        headers=headers,
        json={"reason": "approved two-team seeding"},
    )
    assert seeded.status_code == 200
    fixture = seeded.json()["fixtures"][0]
    assert client.post(
        "/api/attack-defense/operator/tournaments/api-cup/start",
        headers=headers,
        json={"reason": "open competition"},
    ).status_code == 200
    started = client.post(
        f"/api/attack-defense/operator/tournaments/api-cup/fixtures/{fixture['id']}/start",
        headers=headers,
        json={"reason": "teams and checker ready"},
    )
    assert started.status_code == 200
    assert started.json()["status"] == "running"
    finalized = client.post(
        f"/api/attack-defense/operator/tournaments/api-cup/fixtures/{fixture['id']}/finalize",
        headers=headers,
        json={
            "winner_entry_id": "api-entry-1",
            "reason": "referee tie-break decision",
        },
    )
    assert finalized.status_code == 200
    assert finalized.json()["winner_entry_id"] == "api-entry-1"
    public = client.get("/api/attack-defense/public/tournaments/api-cup").json()
    assert public["status"] == "completed"
    assert public["winner_entry_id"] == "api-entry-1"
