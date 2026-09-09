"""Command boundary regression tests. Test telemetry is never shipped as UI data."""

import time
import json
import jwt
import httpx
import pytest
from fastapi.testclient import TestClient
from shared.rbac import Identity
from services.instructor_api import command, command_policy, audit_store, command_store
from services.instructor_api.main import app


@pytest.fixture
def client(monkeypatch, tmp_path):
    for role in ("INSTRUCTOR", "OPERATOR", "COMPETITOR", "RED", "BLUE", "OBSERVER"):
        monkeypatch.setenv(role + "_TOKEN", "command-test-" + role.lower())
    monkeypatch.setenv(
        "AUTH_JWT_SECRET", "command-test-jwt-signing-secret-at-least-32-bytes"
    )
    monkeypatch.delenv("RBAC_TOKENS", raising=False)
    monkeypatch.delenv("RBAC_ALLOW_INSECURE_DEV", raising=False)
    monkeypatch.setattr(audit_store, "DB_PATH", tmp_path / "audit.db")
    audit_store._init_db()
    return TestClient(app)


def headers(role="instructor", team="", match=""):
    if team or match:
        token = jwt.encode(
            {
                "sub": role + "-user",
                "role": role,
                "team_id": team,
                "match_id": match,
                "type": "access",
                "exp": int(time.time()) + 60,
            },
            "command-test-jwt-signing-secret-at-least-32-bytes",
            algorithm="HS256",
        )
    else:
        token = "command-test-" + role
    return {"Authorization": "Bearer " + token}


@pytest.mark.parametrize(
    "path",
    [
        "/session",
        "/snapshot",
        "/stream",
        "/incidents/INC-1",
        "/audit",
        "/replay",
        "/aar",
        "/drafts",
        "/resources/teams",
        "/training",
        "/copilot/policy",
        "/competition",
        "/search?q=ab",
    ],
)
def test_new_reads_fail_closed(client, path):
    assert client.get("/command" + path).status_code == 401


def test_personal_training_is_additive_and_forwards_caller_identity(client, monkeypatch):
    calls = []

    async def fake(service, path, auth, **kwargs):
        calls.append((service, path, auth, kwargs))
        if path == "/portal/training/me":
            return {"scope": "individual", "subject": "red-user", "domains": [], "activity": []}
        return {"challenges": []}

    monkeypatch.setattr(command, "upstream", fake)
    auth = headers("red", "alpha", "exercise-one")
    response = client.get("/command/training", headers=auth)
    assert response.status_code == 200
    assert response.json()["scope"] == "team"  # Retain existing callers' team contract.
    assert response.json()["individual"]["data"]["scope"] == "individual"
    response = client.post("/command/training/challenges/WEB-001/start", headers=auth)
    assert response.status_code == 200
    assert calls[-1][0:2] == ("portal", "/portal/training/challenges/WEB-001/start")
    assert calls[-1][2] == auth["Authorization"]
    assert calls[-1][3]["method"] == "POST"


def test_practice_start_cannot_use_an_unassigned_or_observer_identity(client):
    for role in ("red", "observer", "instructor", "operator"):
        assert client.post("/command/training/challenges/WEB-001/start", headers=headers(role)).status_code == 403


def test_blue_challenge_navigation_uses_the_defensive_catalog(client, monkeypatch):
    calls = []

    async def fake(service, path, auth, **kwargs):
        calls.append(path)
        return {"challenges": []}

    monkeypatch.setattr(command, "upstream", fake)
    response = client.get("/command/resources/challenges", headers=headers("blue", "alpha", "exercise-one"))
    assert response.status_code == 200
    assert calls[-1] == "/portal/blue/challenges"


def test_command_ignores_insecure_dev_bypass(client, monkeypatch):
    for role in ("INSTRUCTOR", "OPERATOR", "COMPETITOR", "RED", "BLUE", "OBSERVER"):
        monkeypatch.delenv(role + "_TOKEN")
    monkeypatch.delenv("AUTH_JWT_SECRET")
    monkeypatch.setenv("RBAC_ALLOW_INSECURE_DEV", "true")
    assert client.get("/command/session").status_code == 401


@pytest.mark.parametrize("role", ["red", "observer", "competitor", "operator"])
def test_no_soc_or_instructor_capability_escalation(client, role):
    session = client.get("/command/session", headers=headers(role)).json()
    assert "control" not in session["capabilities"]
    assert "soc" not in session["capabilities"]
    assert (
        client.get("/command/resources/alerts", headers=headers(role)).status_code
        == 403
    )
    assert client.get("/command/drafts", headers=headers(role)).status_code == 403
    assert client.get(
        "/command/assets/power_plant", headers=headers(role)
    ).status_code in {200, 403}


def test_observer_catalog_has_no_solutions(client):
    response = client.get("/command/assets/power_plant", headers=headers("observer"))
    assert response.json()["vulnerabilities"] == []


def test_unknown_resource_cannot_proxy_url(client):
    assert (
        client.get("/command/resources/http:example.com", headers=headers()).status_code
        == 404
    )


@pytest.mark.parametrize("confirm,reason", [(False, "valid reason"), (True, "   ")])
def test_sensitive_action_requires_confirmation_and_reason(client, confirm, reason):
    response = client.post(
        "/command/control",
        headers=headers(),
        json={"action": "emergency-stop", "reason": reason, "confirm": confirm},
    )
    assert response.status_code == 400


def test_sensitive_action_audits_requested_and_completed(client, monkeypatch):
    calls = []

    async def fake(service, path, auth, **kw):
        calls.append((service, path, kw))
        return {"emergency_stop": True}

    monkeypatch.setattr(command, "upstream", fake)
    r = client.post(
        "/command/control",
        headers=headers(),
        json={
            "action": "emergency-stop",
            "reason": "Safety exercise checkpoint",
            "confirm": True,
        },
    )
    assert r.status_code == 200
    assert calls[0][:2] == ("range", "/safety/emergency-stop")
    actions = {a["action"] for a in audit_store.list_entries()}
    assert actions == {
        "command:emergency-stop:requested",
        "command:emergency-stop:completed",
    }


def test_failed_control_preserves_audit(client, monkeypatch):
    async def fake(*args, **kwargs):
        raise httpx.ConnectError("offline")

    monkeypatch.setattr(command, "upstream", fake)
    r = client.post(
        "/command/control",
        headers=headers(),
        json={"action": "reset", "reason": "new local exercise", "confirm": True},
    )
    assert r.status_code == 502
    assert {r["action"] for r in audit_store.list_entries()} == {
        "command:reset:requested",
        "command:reset:failed",
    }


def test_partial_snapshot_never_invents_healthy_sources(client, monkeypatch):
    async def fake(service, path, auth, **kwargs):
        if service == "auth":
            return {"role": "instructor"}
        if service == "events" and path == "/replay/events":
            return {"events": []}
        raise httpx.ConnectError("offline")

    monkeypatch.setattr(command, "upstream", fake)
    response = client.get("/command/snapshot", headers=headers())
    assert response.status_code == 200
    body = response.json()
    assert body["sources"]["events"]["status"] == "ready"
    assert body["sources"]["safety"]["status"] == "unavailable"
    assert body["sources"]["safety"]["data"] is None
    assert len(body["assets"]) == 11
    assert all(a["health"] is None for a in body["assets"])


def test_blue_cannot_read_or_mutate_other_team_incident(client, monkeypatch):
    async def fake(service, path, *args, **kwargs):
        if service == "auth":
            return {"role": "blue"}
        return {"id": "INC-2", "team_id": "another-team"}

    monkeypatch.setattr(command, "upstream", fake)
    auth = headers("blue", "blue-a", "exercise-a")
    assert client.get("/command/incidents/INC-2", headers=auth).status_code == 404
    assert (
        client.post(
            "/command/incidents/INC-2/note", headers=auth, json={"value": "test"}
        ).status_code
        == 404
    )


def test_blue_incident_transition_preserves_server_contract(client, monkeypatch):
    calls = []

    async def fake(service, path, *args, **kwargs):
        calls.append((service, path, kwargs))
        return {"id": "INC-1", "team_id": "blue-a", "status": "triage"}

    monkeypatch.setattr(command, "upstream", fake)
    response = client.post(
        "/command/incidents/INC-1/transition",
        headers=headers("blue", "blue-a", "exercise-a"),
        json={"value": "triage", "note": "Reviewed source evidence"},
    )
    assert response.status_code == 200
    assert calls[-1][2]["body"] == {"to": "triage", "note": "Reviewed source evidence"}


def test_revoked_jwt_is_rejected_before_any_data_fetch(client, monkeypatch):
    async def fake(*args, **kwargs):
        req = httpx.Request("GET", "http://auth/auth/me")
        r = httpx.Response(401, request=req)
        raise httpx.HTTPStatusError("revoked", request=req, response=r)

    monkeypatch.setattr(command, "upstream", fake)
    assert (
        client.get("/command/session", headers=headers("blue", "b", "m")).status_code
        == 401
    )


def test_missing_team_scope_is_not_assumed(client):
    assert client.get("/command/snapshot", headers=headers("red")).status_code == 403


def test_red_projection_rejects_blue_and_wrong_match():
    ident = Identity(actor="red-a", role="red", team_id="a", match_id="m")
    event = {
        "event_id": "e",
        "event_type": "red_attack_started",
        "timestamp": 1,
        "actor": "red",
        "team_id": "a",
        "scenario_id": "m",
        "metadata": '{"mitre":["T1190"]}',
    }
    assert command_policy.project_event(event, ident, now=100)["metadata"]["mitre"] == [
        "T1190"
    ]
    assert (
        command_policy.project_event({**event, "actor": "blue"}, ident, now=100) is None
    )
    assert (
        command_policy.project_event({**event, "scenario_id": "other"}, ident, now=100)
        is None
    )
    assert (
        command_policy.project_event({**event, "team_id": "other"}, ident, now=100)
        is None
    )


def test_observer_delay_and_field_allowlist():
    observer = Identity("o", "observer")
    event = {
        "event_id": "e",
        "event_type": "asset_compromised",
        "timestamp": 80,
        "target_asset": "power_plant",
        "metadata": {"flag": "private"},
        "team_id": "private-team",
        "trace_id": "private-trace",
    }
    assert command_policy.project_event(event, observer, now=100) is None
    public = command_policy.project_event(event, observer, now=120)
    assert public["metadata"] == {}
    assert "team_id" not in public and "trace_id" not in public
    assert "private" not in json.dumps(public)


def test_competition_observer_never_calls_operator_paths(client, monkeypatch):
    paths = []

    async def fake(service, path, *args, **kwargs):
        paths.append(path)
        return {}

    monkeypatch.setattr(command, "upstream", fake)
    r = client.get("/command/competition", headers=headers("observer"))
    assert r.status_code == 200
    assert paths and all("/operator/" not in p for p in paths)
    assert not any("/patches" in p for p in paths)


def test_competitor_cannot_select_another_match(client, monkeypatch):
    async def fake(*args, **kwargs):
        return {}

    monkeypatch.setattr(command, "upstream", fake)
    assert (
        client.get(
            "/command/competition?match_id=foreign",
            headers=headers("competitor", "t", "own"),
        ).status_code
        == 403
    )


def test_ai_disabled_by_default(client, monkeypatch):
    monkeypatch.delenv("COMMAND_AI_URL", raising=False)
    monkeypatch.delenv("COMMAND_AI_MODEL", raising=False)
    r = client.post(
        "/command/copilot",
        headers=headers(),
        json={"mode": "instructor", "question": "Summarize this exercise"},
    )
    assert r.status_code == 503
    assert command_store.get("policy", "platform", "copilot") is None


def test_drafts_are_private_to_actor(client, monkeypatch):
    source = "scenario:\n  id: X\n  private: keep exactly\n"
    assert (
        client.post(
            "/command/scenarios/X/draft", headers=headers(), json={"yaml": source}
        ).status_code
        == 200
    )
    assert (
        client.get("/command/drafts", headers=headers()).json()["drafts"][0]["yaml"]
        == source
    )
    assert client.get("/command/drafts", headers=headers("red")).status_code == 403
