from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from services.attack_defense.api import create_app
from services.attack_defense.evidence import AuditContext
from services.attack_defense.rate_limit import DistributedRateLimiter

from .conftest import bootstrap


def test_sqlite_match_lease_excludes_another_owner(ad):
    with ad.db.match_lock("match-1", "engine-a", 30) as first:
        assert first is True
        with ad.db.match_lock("match-1", "engine-b", 30) as second:
            assert second is False

    with ad.db.match_lock("match-1", "engine-b", 30) as acquired_after_release:
        assert acquired_after_release is True


def test_database_rate_limit_counter_is_shared_by_instances(ad):
    first = DistributedRateLimiter(ad.db)
    second = DistributedRateLimiter(ad.db)

    decisions = [
        (first if index % 2 else second).consume(
            "team-01", "flag_submit", window_seconds=60, limit=3
        )
        for index in range(1, 6)
    ]

    assert [item.count for item in decisions] == [1, 2, 3, 4, 5]
    assert [item.allowed for item in decisions] == [True, True, True, False, False]
    assert all(item.retry_after_seconds == 60 for item in decisions)


def test_audit_stream_has_stable_sequence_without_sqlite_rowid(ad):
    for index in range(3):
        ad.evidence.record(
            AuditContext(
                actor="coordination-test",
                event_type="ha_event",
                result="success",
                event_id=f"ha-event-{index}",
            )
        )

    conn = ad.db.connect()
    try:
        rows = conn.execute(
            "SELECT sequence,event_id FROM audit_event_stream ORDER BY sequence"
        ).fetchall()
    finally:
        conn.close()

    assert [row["event_id"] for row in rows] == [
        "ha-event-0", "ha-event-1", "ha-event-2"
    ]
    assert [row["sequence"] for row in rows] == sorted(
        {row["sequence"] for row in rows}
    )


def test_runtime_reclaim_rotates_token_and_rejects_stale_completion(ad):
    bootstrap(ad, teams=2, services=1)
    patch = ad.patches.submit(
        "match-1",
        "team-1",
        "service-vulnerable-notes",
        "registry.local:5000/team-01/vulnerable-notes:ha-patch",
        "competitor",
    )
    ad.patches.inspect_and_queue(patch["id"])

    first_claim = ad.patches.claim_job("runner-a")
    assert first_claim is not None
    first_token = json.loads(first_claim["result"])["claim_token"]
    with ad.db.transaction(immediate=True) as conn:
        conn.execute(
            "UPDATE runtime_jobs SET started_at=0 WHERE id=?", (first_claim["id"],)
        )

    second_claim = ad.patches.claim_job("runner-b")
    assert second_claim is not None
    second_token = json.loads(second_claim["result"])["claim_token"]
    assert second_token != first_token

    with pytest.raises(ValueError, match="stale"):
        ad.patches.complete_job(
            first_claim["id"], False, {"error_code": "stale-runner"},
            claim_token=first_token,
        )
    result = ad.patches.complete_job(
        second_claim["id"], False, {"error_code": "active-runner"},
        claim_token=second_token,
    )
    assert result["status"] == "rejected"


def test_readiness_and_ha_status_expose_no_database_secret(ad):
    client = TestClient(create_app(ad))
    ready = client.get("/ready")
    assert ready.status_code == 200
    assert ready.json()["database_backend"] == "sqlite"

    response = client.get(
        "/api/attack-defense/operator/ha/status",
        headers={"Authorization": "Bearer dev-instructor-token"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ha_capable"] is False
    assert "database_url" not in body
    assert "password" not in response.text.lower()
