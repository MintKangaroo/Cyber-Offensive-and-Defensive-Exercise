from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import jwt
from fastapi.testclient import TestClient

from services.attack_defense.api import create_app
from services.attack_defense.network_policy import ContainerPolicySpec, validate_container_policy

from .conftest import bootstrap


SECRET = "unit-test-jwt-secret-with-enough-entropy"


def token(role: str, team_id: str = "", match_id: str = "") -> str:
    import time
    return jwt.encode(
        {
            "sub": f"{role}-{team_id or 'user'}", "role": role,
            "team_id": team_id, "match_id": match_id, "type": "access",
            "exp": int(time.time()) + 300,
        },
        SECRET, algorithm="HS256",
    )


def test_competitor_cannot_use_operator_api(ad, monkeypatch):
    bootstrap(ad)
    monkeypatch.setenv("AUTH_JWT_SECRET", SECRET)
    client = TestClient(create_app(ad))
    headers = {"Authorization": f"Bearer {token('competitor', 'team-1', 'match-1')}"}
    assert client.get("/api/attack-defense/operator/matches", headers=headers).status_code == 403


def test_cross_match_and_other_team_patch_access_denied(ad, monkeypatch):
    bootstrap(ad)
    monkeypatch.setenv("AUTH_JWT_SECRET", SECRET)
    client = TestClient(create_app(ad))
    wrong_match = {"Authorization": f"Bearer {token('competitor', 'team-1', 'other')}"}
    assert client.get(
        "/api/attack-defense/matches/match-1/state", headers=wrong_match
    ).status_code == 403
    patch = ad.patches.submit(
        "match-1", "team-2", "service-vulnerable-notes",
        "registry.local:5000/team-02/vulnerable-notes:p1", "team-2-user",
    )
    team_one = {"Authorization": f"Bearer {token('competitor', 'team-1', 'match-1')}"}
    assert client.get(
        f"/api/attack-defense/matches/match-1/patches/{patch['id']}", headers=team_one
    ).status_code == 404


def test_public_service_summary_is_aggregate_only(ad):
    bootstrap(ad, teams=2, services=1)
    with ad.db.transaction(immediate=True) as conn:
        conn.execute(
            """UPDATE team_service_instances SET status='healthy'
               WHERE team_id='team-1'"""
        )
        conn.execute(
            """UPDATE team_service_instances SET status='degraded'
               WHERE team_id='team-2'"""
        )
    client = TestClient(create_app(ad))
    response = client.get(
        "/api/attack-defense/public/matches/match-1/service-summary"
    )
    assert response.status_code == 200
    body = response.json()
    assert body["disclosure"] == "aggregate-only"
    assert body["services"][0]["healthy"] == 1
    assert body["services"][0]["degraded"] == 1
    serialized = response.text
    assert "team_id" not in serialized
    assert "endpoint" not in serialized
    assert "image_digest" not in serialized


def test_broadcast_snapshot_uses_only_public_delayed_projections(ad):
    bootstrap(ad, teams=2, services=1)
    with ad.db.transaction(immediate=True) as conn:
        conn.execute(
            "UPDATE matches SET config=? WHERE id='match-1'",
            ('{"scoreboard_delay_rounds":3}',),
        )
        conn.execute(
            """UPDATE team_service_instances
               SET status=CASE WHEN team_id='team-1' THEN 'healthy' ELSE 'degraded' END,
                   endpoint='http://private-runtime:9000',
                   management_endpoint='http://private-runtime:9001',
                   image_digest='sha256:private-image'"""
        )
    client = TestClient(create_app(ad))
    response = client.get(
        "/api/attack-defense/public/matches/match-1/broadcast"
    )
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-robots-tag"] == "noindex, nofollow"
    body = response.json()
    assert body["schema_version"] == "broadcast-overlay.v1"
    assert body["scoreboard"] == client.get(
        "/api/attack-defense/matches/match-1/scoreboard"
    ).json()
    assert body["services"] == client.get(
        "/api/attack-defense/public/matches/match-1/service-summary"
    ).json()["services"]
    assert body["disclosure"] == {
        "audience": "public-broadcast",
        "scoreboard": "delayed-public-projection",
        "scoreboard_delay_rounds": 3,
        "last_public_round": 0,
        "services": "aggregate-only",
        "events_included": False,
        "sensitive_fields_included": False,
    }
    assert body["services"][0]["healthy"] == 1
    assert body["services"][0]["degraded"] == 1
    serialized = response.text
    for private_field in (
        "endpoint", "management_endpoint", "image_digest", "checker_type",
        "identity_subject", "validation_result", "event_id",
    ):
        assert private_field not in serialized
    assert client.get(
        "/api/attack-defense/public/matches/missing/broadcast"
    ).status_code == 404


def test_patch_submission_enters_durable_validation_queue(ad, monkeypatch):
    bootstrap(ad, teams=2, services=1)
    monkeypatch.setenv("AUTH_JWT_SECRET", SECRET)
    client = TestClient(create_app(ad))
    headers = {
        "Authorization": f"Bearer {token('competitor', 'team-1', 'match-1')}"
    }
    response = client.post(
        "/api/attack-defense/matches/match-1/"
        "services/service-vulnerable-notes/patches",
        headers=headers,
        json={
            "image_reference":
                "registry.local:5000/team-01/vulnerable-notes:patch-queued"
        },
    )
    assert response.status_code == 202
    patch_id = response.json()["id"]
    patch = ad.patches.get(patch_id)
    assert patch["status"] == "validating"
    conn = ad.db.connect()
    job = conn.execute(
        "SELECT status FROM runtime_jobs WHERE operation='sandbox_validate'"
    ).fetchone()
    conn.close()
    assert job is not None and job["status"] == "pending"


def test_malformed_future_expired_and_cross_match_flags_are_generic(ad):
    bootstrap(ad, teams=2, services=1)
    with ad.db.transaction(immediate=True) as conn:
        conn.execute("UPDATE matches SET status='running' WHERE id='match-1'")
    current = ad.repo.create_round("match-1")
    ad.repo.transition_round(current["id"], "initializing")
    import time
    ad.repo.transition_round(
        current["id"], "active", {"starts_at": time.time(), "ends_at": time.time() + 30}
    )
    malformed = ad.flags.validate_submission("match-1", "team-1", "FLAG{x}", "actor")
    assert not malformed.accepted
    flag = ad.flags.issue_flag(
        "match-1", current["id"], "team-2", "service-vulnerable-notes"
    )
    ad.flags.mark_injected(flag.id, True)
    with ad.db.transaction(immediate=True) as conn:
        conn.execute("UPDATE flags SET status='expired' WHERE id=?", (flag.id,))
    expired = ad.flags.validate_submission("match-1", "team-1", flag.token, "actor")
    assert not expired.accepted


def test_future_round_and_cross_match_flags_are_rejected(ad):
    bootstrap(ad, teams=2, services=1)
    with ad.db.transaction(immediate=True) as conn:
        conn.execute("UPDATE matches SET status='running' WHERE id='match-1'")
    current = ad.repo.create_round("match-1")
    ad.repo.transition_round(current["id"], "initializing")
    import time
    ad.repo.transition_round(
        current["id"], "active",
        {"starts_at": time.time(), "ends_at": time.time() + 30},
    )
    with ad.db.transaction(immediate=True) as conn:
        conn.execute(
            """INSERT INTO rounds(
               id,match_id,sequence,status,correlation_id,created_at
               ) VALUES('future-round','match-1',2,'pending','future-correlation',?)""",
            (ad.db.server_time(conn),),
        )
    future_flag = ad.flags.issue_flag(
        "match-1", "future-round", "team-2", "service-vulnerable-notes"
    )
    ad.flags.mark_injected(future_flag.id, True)
    rejected_future = ad.flags.validate_submission(
        "match-1", "team-1", future_flag.token, "actor"
    )
    assert not rejected_future.accepted
    assert rejected_future.reason == "expired_or_future"

    ad.repo.create_match(
        "Other Match", 5, 3, {}, "other-match", "attack_defense"
    )
    ad.repo.add_team(
        "other-match", "other-team-1", "Other Team 1", "other-team-1"
    )
    ad.repo.add_team(
        "other-match", "other-team-2", "Other Team 2", "other-team-2"
    )
    ad.repo.add_service(
        "other-match", "other-notes", "Other Notes",
        "registry.local/base/vulnerable-notes:v1", 9000,
        "vulnerable_notes", {}, service_id="other-service-notes",
    )
    with ad.db.transaction(immediate=True) as conn:
        conn.execute("UPDATE matches SET status='running' WHERE id='other-match'")
    other_round = ad.repo.create_round("other-match")
    other_flag = ad.flags.issue_flag(
        "other-match", other_round["id"], "other-team-2",
        "other-service-notes",
    )
    cross_match = ad.flags.validate_submission(
        "match-1", "team-1", other_flag.token, "actor"
    )
    assert not cross_match.accepted
    assert cross_match.reason == "invalid_or_inactive"


def test_wall_clock_expired_and_disabled_service_flags_are_rejected(ad):
    bootstrap(ad, teams=3, services=1)
    with ad.db.transaction(immediate=True) as conn:
        conn.execute("UPDATE matches SET status='running' WHERE id='match-1'")
    current = ad.repo.create_round("match-1")
    ad.repo.transition_round(current["id"], "initializing")
    import time
    ad.repo.transition_round(
        current["id"], "active",
        {"starts_at": time.time(), "ends_at": time.time() + 30},
    )
    flag = ad.flags.issue_flag(
        "match-1", current["id"], "team-2", "service-vulnerable-notes"
    )
    ad.flags.mark_injected(flag.id, True)
    disabled_flag = ad.flags.issue_flag(
        "match-1", current["id"], "team-3", "service-vulnerable-notes"
    )
    ad.flags.mark_injected(disabled_flag.id, True)
    with ad.db.transaction(immediate=True) as conn:
        conn.execute("UPDATE flags SET valid_until=0 WHERE id=?", (flag.id,))
    expired = ad.flags.validate_submission(
        "match-1", "team-1", flag.token, "actor"
    )
    assert not expired.accepted and expired.reason == "expired_or_future"

    with ad.db.transaction(immediate=True) as conn:
        conn.execute(
            "UPDATE game_services SET enabled=0 WHERE id='service-vulnerable-notes'"
        )
    disabled = ad.flags.validate_submission(
        "match-1", "team-2", disabled_flag.token, "actor"
    )
    assert not disabled.accepted and disabled.reason == "service_disabled"


def test_concurrent_submission_only_awards_once(ad):
    bootstrap(ad, teams=2, services=1)
    ad.engine.start_match("match-1", "operator")
    current = ad.repo.current_round("match-1")
    conn = ad.db.connect()
    row = dict(conn.execute(
        "SELECT * FROM flags WHERE round_id=? AND team_id='team-2' LIMIT 1",
        (current["id"],),
    ).fetchone())
    conn.close()
    value = ad.flags.reconstruct(row)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(
            lambda _: ad.flags.validate_submission("match-1", "team-1", value, "actor"),
            range(16),
        ))
    assert sum(r.accepted for r in results) == 1
    assert sum(r.score_delta for r in results) == 10


def test_flag_submission_rate_limit_is_persistent(ad, monkeypatch):
    bootstrap(ad, teams=2, services=1)
    monkeypatch.setenv("AUTH_JWT_SECRET", SECRET)
    ad.settings = replace(ad.settings, max_flag_submissions_per_minute=2)
    client = TestClient(create_app(ad))
    headers = {
        "Authorization": f"Bearer {token('competitor', 'team-1', 'match-1')}"
    }
    path = "/api/attack-defense/matches/match-1/flags/submit"
    assert client.post(path, headers=headers, json={"flag": "FLAG{x}"}).status_code == 200
    assert client.post(path, headers=headers, json={"flag": "FLAG{x}"}).status_code == 200
    limited = client.post(path, headers=headers, json={"flag": "FLAG{x}"})
    assert limited.status_code == 429
    assert limited.headers["retry-after"] == "60"


def test_mutating_payload_size_limit(ad):
    client = TestClient(create_app(ad))
    response = client.post(
        "/api/attack-defense/matches",
        content=b"x" * 16_385,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413


def test_dangerous_container_settings_rejected():
    result = validate_container_policy(ContainerPolicySpec(
        privileged=True, network_mode="host", pid_mode="host",
        cap_add=("SYS_ADMIN",), mounts=("/var/run/docker.sock:/sock",),
        security_options=(),
    ))
    assert not result.allowed
    assert {
        "privileged_forbidden", "host_network_forbidden", "host_pid_forbidden",
        "capability_add_forbidden", "host_mount_forbidden",
        "no_new_privileges_required",
    }.issubset(set(result.violations))
