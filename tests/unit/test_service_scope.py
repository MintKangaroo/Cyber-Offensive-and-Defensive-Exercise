"""Direct-service authorization and durable stream tests use isolated test evidence."""

import asyncio
import json
import time
from datetime import datetime, timezone

import httpx
import jwt
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from shared import scope
from shared.rbac import Identity
from shared.service_auth import range_agent_signature

SECRET = "scope-test-signing-key-32-bytes-long-enough"  # training-only fixture
MASTER = "scope-test-service-master"


def auth(role="blue", team="alpha", scenario="exercise-a"):
    return {
        "Authorization": "Bearer "
        + jwt.encode(
            {
                "sub": role + "-user",
                "role": role,
                "team_id": team,
                "match_id": scenario,
                "type": "access",
                "exp": time.time() + 120,
            },
            SECRET,
            algorithm="HS256",
        )
    }


def sensor(asset):
    return {
        "Authorization": "RangeAgent "
        + asset
        + ":"
        + range_agent_signature(MASTER, asset)
    }


@pytest.fixture(autouse=True)
def strict(monkeypatch, tmp_path):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("RANGE_SCOPE_ENFORCE", "true")
    monkeypatch.setenv("AUTH_JWT_SECRET", SECRET)
    monkeypatch.setenv("SERVICE_TOKEN", MASTER)
    monkeypatch.setenv("INSTRUCTOR_TOKEN", "scope-test-instructor")
    monkeypatch.setenv("BLUE_TOKEN", "scope-test-static-blue")
    monkeypatch.delenv("RBAC_TOKENS", raising=False)
    monkeypatch.delenv("RBAC_ALLOW_INSECURE_DEV", raising=False)
    monkeypatch.setenv(
        "RANGE_ASSET_SCOPES",
        json.dumps(
            {
                "asset-a": {"team_id": "alpha", "scenario_id": "exercise-a"},
                "asset-b": {"team_id": "bravo", "scenario_id": "exercise-a"},
                "asset-old": {"team_id": "alpha", "scenario_id": "exercise-b"},
            }
        ),
    )

    async def verified(_):
        pass

    monkeypatch.setattr(scope, "verify_session", verified)


@pytest.fixture
def collector(monkeypatch, tmp_path):
    from services.event_collector import main as mod

    monkeypatch.setattr(mod, "DB_PATH", tmp_path / "events.db")
    monkeypatch.setattr(mod, "_writer_conn", None)
    mod.init_db()
    yield mod, TestClient(mod.app)
    if mod._writer_conn:
        mod._writer_conn.close()


def populate(mod, records):
    from shared.event_schema import Event

    events = [
        Event(
            event_id=r.get("event_id", str(i)),
            event_type=r.get("event_type", "asset_compromised"),
            timestamp=r.get("timestamp", time.time() - 60),
            actor=r.get("actor", "red"),
            team_id=r.get("team_id", "alpha"),
            scenario_id=r.get("scenario_id", "exercise-a"),
            target_asset="asset-a",
            metadata={"evidence": "private"},
        )
        for i, r in enumerate(records)
    ]
    assert all(mod._persist_batch(events))
    return events


def test_direct_collector_reads_enforce_both_membership_dimensions(collector):
    mod, client = collector
    populate(
        mod,
        [
            {},
            {"team_id": "bravo"},
            {"scenario_id": "exercise-b"},
            {"actor": "blue"},
            {"team_id": ""},
        ],
    )
    assert client.get("/events").status_code == 401
    assert (
        client.get(
            "/events", headers={"Authorization": "Bearer scope-test-static-blue"}
        ).status_code
        == 403
    )
    assert [
        e["event_id"] for e in client.get("/events", headers=auth()).json()["events"]
    ] == ["3", "0"]
    assert [
        e["event_id"]
        for e in client.get("/events", headers=auth("red")).json()["events"]
    ] == ["0"]
    assert client.get("/events?team_id=bravo", headers=auth()).status_code == 403
    assert (
        client.get("/replay/events?scenario_id=exercise-b", headers=auth()).status_code
        == 403
    )
    assert client.get("/metrics", headers=auth("observer")).status_code == 403
    assert (
        len(
            client.get("/events", headers={"Authorization": "Bearer " + MASTER}).json()[
                "events"
            ]
        )
        == 5
    )


def test_observer_minimum_delay_and_payload_projection(collector):
    mod, client = collector
    populate(
        mod,
        [
            {},
            {"timestamp": time.time()},
            {"event_type": "blue_detection_success"},
            {"scenario_id": "exercise-b"},
        ],
    )
    for path in ("/events", "/events/delayed?delay_sec=0", "/replay/events"):
        result = client.get(path, headers=auth("observer")).json()
        assert len(result["events"]) == 1
        assert result["events"][0]["metadata"] == {}
        assert "team_id" not in result["events"][0]
    assert (
        client.get("/events/delayed?delay_sec=0", headers=auth("observer")).json()[
            "delay_sec"
        ]
        >= 30
    )


def test_stable_replay_pages_cursor_tamper_and_cross_team_denial(collector):
    mod, client = collector
    populate(mod, [{"timestamp": 100 + i} for i in range(7)] + [{"team_id": "bravo"}])
    first = client.get("/replay/page?limit=2", headers=auth()).json()
    assert [e["event_id"] for e in first["events"]] == ["0", "1"]
    # Late arriving evidence is held for the next snapshot, even when its timestamp sorts earlier.
    populate(mod, [{"event_id": "late", "timestamp": 100.5}])
    cursor = first["next_cursor"]
    events = first["events"]
    assert (
        client.get(
            "/replay/page", params={"cursor": cursor}, headers=auth(team="bravo")
        ).status_code
        == 403
    )
    assert (
        client.get(
            "/replay/page", params={"cursor": cursor + "bad"}, headers=auth()
        ).status_code
        == 400
    )
    while cursor:
        result = client.get(
            "/replay/page", params={"cursor": cursor, "limit": 2}, headers=auth()
        ).json()
        events.extend(result["events"])
        cursor = result["next_cursor"]
    assert [e["event_id"] for e in events] == list(map(str, range(7)))
    assert result["complete"] is True


def test_durable_journal_dedup_restart_and_reset_sequence(collector):
    from services.event_collector import journal

    mod, client = collector
    ev = populate(mod, [{}, {}])
    assert mod._persist_batch(ev) == [False, False]
    mod._writer_conn.close()
    mod._writer_conn = None
    mod.init_db()
    conn = mod.get_db()
    assert len(journal.messages(conn, 0)) == 2
    before = journal.bounds(conn)[1]
    conn.close()
    assert (
        client.post(
            "/admin/reset",
            headers={"Authorization": "Bearer scope-test-instructor"},
            json={"confirm": True, "reason": "test reset"},
        ).status_code
        == 200
    )
    populate(mod, [{"event_id": "next"}])
    conn = mod.get_db()
    resumed = journal.messages(conn, before)
    assert [m["topic"] for m in resumed] == ["safety", "events"]
    assert resumed[0]["data"]["action"] == "range-reset"
    assert resumed[1]["data"]["event_id"] == "next"
    assert all(m["id"] > before for m in resumed)
    conn.close()


@pytest.mark.parametrize(
    "service,path",
    [
        ("services.event_collector.main", "/ws"),
        ("services.siem.api.main", "/ws/logs"),
        ("services.siem.api.main", "/ws/alerts"),
        ("services.edr.api.main", "/edr/ws"),
    ],
)
def test_websockets_fail_closed_without_identity(service, path):
    import importlib

    client = TestClient(importlib.import_module(service).app)
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect(path):
            pass
    assert exc.value.code == 4401


def test_siem_search_alert_detail_status_and_aggregates(monkeypatch, tmp_path):
    from services.siem.api import main as mod
    from services.siem.storage.sqlite_backend import SqliteBackend
    from services.siem.storage.alert_store import AlertStore
    from shared.siem_schema import NormalizedEvent

    monkeypatch.setattr(mod, "backend", SqliteBackend(str(tmp_path / "siem.db")))
    monkeypatch.setattr(mod, "alert_store", AlertStore(str(tmp_path / "alerts.db")))
    now = datetime.now(timezone.utc)
    ids = []
    for i, (team, scenario) in enumerate(
        [
            ("alpha", "exercise-a"),
            ("bravo", "exercise-a"),
            ("alpha", "exercise-b"),
            ("", ""),
        ]
    ):
        e = NormalizedEvent(
            event_id=str(i),
            timestamp=now,
            ingested_at=now,
            source_type="twin",
            team_id=team,
            scenario_id=scenario,
            message="scope evidence",
        )
        asyncio.run(mod.backend.index(e))
        ids.append(
            mod.alert_store.save(
                "R1",
                "Scope evidence",
                3,
                [],
                time.time(),
                "detail",
                e.model_dump(mode="json"),
            )
        )
    client = TestClient(mod.app)
    assert client.get("/search?text=evidence", headers=auth()).json()["total"] == 1
    assert len(client.get("/alerts", headers=auth()).json()["alerts"]) == 1
    assert client.get("/alerts/" + ids[1], headers=auth()).status_code == 404
    assert (
        client.post("/alerts/" + ids[1] + "?status=closed", headers=auth()).status_code
        == 404
    )
    assert client.post("/alerts/" + ids[0] + "?status=ack", headers=auth()).json()[
        "updated"
    ]
    stats = client.get("/stats", headers=auth()).json()
    assert stats["events_by_source"] == {"twin": 1}
    assert stats["alerts_by_severity"] == {"3": 1}
    assert client.get("/search", headers=auth("red")).status_code == 403
    assert client.get("/sources/health", headers=auth()).status_code == 403


def test_edr_sensor_credentials_are_asset_scoped_and_team_actions_guarded(
    monkeypatch, tmp_path
):
    from services.edr.api import main as mod

    monkeypatch.setattr(mod, "DB_PATH", tmp_path / "edr.db")
    mod.init_db()
    client = TestClient(mod.app)
    for asset in ("asset-a", "asset-b", "asset-old", "unowned"):
        assert (
            client.post(
                "/edr/ingest",
                headers=sensor(asset),
                json={
                    "asset": asset,
                    "timestamp": time.time(),
                    "processes": [],
                    "team_id": "forged",
                    "scenario_id": "forged",
                },
            ).status_code
            == 200
        )
    assert (
        client.post(
            "/edr/ingest",
            headers=sensor("asset-a"),
            json={"asset": "asset-b", "timestamp": time.time(), "processes": []},
        ).status_code
        == 404
    )
    assert [
        h["asset"] for h in client.get("/edr/hosts", headers=auth()).json()["hosts"]
    ] == ["asset-a"]
    for path in ("/processes", "/timeline", "/kill-commands"):
        assert (
            client.get("/edr/hosts/asset-b" + path, headers=auth()).status_code == 404
        )
    for path in ("/isolate", "/unisolate", "/process/22/kill"):
        assert (
            client.post(
                "/edr/hosts/asset-b" + path, headers=auth(), json={"reason": "test"}
            ).status_code
            == 404
        )
    assert client.get("/edr/audit", headers=auth()).status_code == 403
    assert (
        client.get(
            "/edr/hosts/asset-a/kill-commands/pending", headers=sensor("asset-b")
        ).status_code
        == 403
    )
    assert client.get("/edr/hosts", headers=sensor("asset-a")).status_code == 403
    assert (
        client.post(
            "/edr/kill-commands/unknown/ack", headers=auth(), json={"status": "done"}
        ).status_code
        == 403
    )


def test_config_sensors_cannot_read_other_assets_or_write(monkeypatch, tmp_path):
    from services.config_service import main as mod

    monkeypatch.setattr(mod, "DB_PATH", tmp_path / "config.db")
    mod.init_db()
    client = TestClient(mod.app)
    assert (
        client.get(
            "/config/patches?asset=asset-a", headers=sensor("asset-a")
        ).status_code
        == 200
    )
    for path in (
        "/config/patches",
        "/config/patches?asset=asset-b",
        "/config/patches?asset=asset-a&asset=asset-b",
        "/instructor/audit",
    ):
        assert client.get(path, headers=sensor("asset-a")).status_code == 403
    assert (
        client.get("/config/patches?asset=asset-b", headers=auth()).status_code == 404
    )
    assert (
        client.get("/config/killswitch", headers=sensor("asset-a")).status_code == 200
    )
    assert (
        client.post(
            "/instructor/killswitch",
            headers=sensor("asset-a"),
            json={"reason": "forbidden"},
        ).status_code
        == 403
    )


def test_incident_scope_persists_and_lifecycle_denies_cross_exercise(
    monkeypatch, tmp_path
):
    from services.incident import main as mod

    monkeypatch.setattr(mod, "DB_PATH", tmp_path / "incidents.db")
    mod._init()

    async def emit(*_):
        pass

    monkeypatch.setattr(mod, "_emit", emit)
    client = TestClient(mod.app)
    ids = []
    for i, (team, scenario) in enumerate(
        [
            ("alpha", "exercise-a"),
            ("bravo", "exercise-a"),
            ("alpha", "exercise-b"),
            ("alpha", ""),
        ]
    ):
        r = client.post(
            "/incidents/from-alert",
            headers={"Authorization": "Bearer scope-test-instructor"},
            json={
                "alert_id": str(i),
                "title": "case",
                "team_id": team,
                "scenario_id": scenario,
            },
        )
        assert r.status_code == 200, r.text
        ids.append(r.json()["id"])
    assert [
        r["id"] for r in client.get("/incidents", headers=auth()).json()["incidents"]
    ] == ids[:1]
    assert (
        client.get("/incidents/" + ids[0], headers=auth()).json()["scenario_id"]
        == "exercise-a"
    )
    for iid in ids[1:]:
        assert client.get("/incidents/" + iid, headers=auth()).status_code == 404
        for action, payload in (
            ("note", {"note": "secret"}),
            ("transition", {"to": "triage"}),
            ("assign", {"assignee": "someone"}),
        ):
            assert client.post(
                "/incidents/" + iid + "/" + action, headers=auth(), json=payload
            ).status_code in {400, 404}
    assert client.get("/incidents?team_id=bravo", headers=auth()).status_code == 403


def test_inject_inbox_and_response_check_membership_not_request_text(
    monkeypatch, tmp_path
):
    from services.injects import main as mod

    monkeypatch.setattr(mod, "DB_PATH", tmp_path / "injects.db")
    mod._init()
    client = TestClient(mod.app)
    ids = []
    for team, scenario in [
        ("alpha", "exercise-a"),
        ("bravo", "exercise-a"),
        ("alpha", "exercise-b"),
    ]:
        r = client.post(
            "/injects/dispatch",
            headers={"Authorization": "Bearer scope-test-instructor"},
            json={"team_ids": [team], "scenario_id": scenario, "subject": "test"},
        )
        assert r.status_code == 200, r.text
        ids.append(r.json()["injects"][0]["id"])
    assert client.get("/injects/inbox?team_id=bravo", headers=auth()).status_code == 403
    assert (
        client.get("/injects/inbox?team_id=alpha", headers=auth()).json()["count"] == 1
    )
    assert (
        client.post(
            "/injects/" + ids[1] + "/respond",
            headers=auth(),
            json={"team_id": "bravo", "response_text": "forged"},
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/injects/" + ids[2] + "/respond",
            headers=auth(),
            json={"team_id": "alpha", "response_text": "wrong exercise"},
        ).status_code
        == 404
    )
    assert (
        client.post(
            "/injects/" + ids[0] + "/respond",
            headers=auth(),
            json={"team_id": "alpha", "response_text": "actual response"},
        ).status_code
        == 200
    )


def test_safety_actions_require_confirmation_and_keep_durable_audit(
    monkeypatch, tmp_path
):
    from services.config_service import main as mod

    monkeypatch.setattr(mod, "DB_PATH", tmp_path / "config.db")
    mod.init_db()
    client = TestClient(mod.app)
    headers = {"Authorization": "Bearer scope-test-instructor"}
    for payload in (
        {},
        {"reason": "test reason"},
        {"confirm": True, "reason": "  "},
        {"confirm": "true", "reason": "test reason"},
    ):
        assert (
            client.post(
                "/instructor/killswitch", headers=headers, json=payload
            ).status_code
            == 400
        )
        assert (
            client.get("/config/killswitch", headers=headers).json()["killswitch"]
            is False
        )
    assert (
        client.post(
            "/instructor/killswitch",
            headers=headers,
            json={"confirm": True, "reason": "exercise safety test"},
        ).status_code
        == 200
    )
    audit = [
        json.loads(line)
        for line in (tmp_path / "security-actions.jsonl").read_text().splitlines()
    ]
    assert [a["status"] for a in audit] == ["requested", "completed"]
    assert all(
        a["actor"] == "instructor" and a["reason"] == "exercise safety test"
        for a in audit
    )
    assert (
        client.post(
            "/admin/reset",
            headers=headers,
            json={"confirm": True, "reason": "authorized reset"},
        ).status_code
        == 200
    )
    assert len((tmp_path / "security-actions.jsonl").read_text().splitlines()) == 4


def test_audit_storage_failure_prevents_safety_action(monkeypatch, tmp_path):
    from shared import action_guard
    from services.config_service import main as mod

    monkeypatch.setattr(mod, "DB_PATH", tmp_path / "config.db")
    mod.init_db()

    def unavailable(_):
        raise HTTPException(503, "audit unavailable")

    monkeypatch.setattr(action_guard, "record", unavailable)
    client = TestClient(mod.app)
    h = {"Authorization": "Bearer scope-test-instructor"}
    assert (
        client.post(
            "/instructor/killswitch",
            headers=h,
            json={"confirm": True, "reason": "exercise safety test"},
        ).status_code
        == 503
    )
    assert client.get("/config/killswitch", headers=h).json()["killswitch"] is False


def test_expired_and_forged_identities_never_reach_the_collector(collector):
    _, client = collector
    for token in (
        "invalid",
        jwt.encode(
            {"role": "instructor", "exp": time.time() - 1}, SECRET, algorithm="HS256"
        ),
        jwt.encode(
            {"role": "instructor", "exp": time.time() + 60},
            "incorrect-secret",
            algorithm="HS256",
        ),
    ):
        assert (
            client.get(
                "/events", headers={"Authorization": "Bearer " + token}
            ).status_code
            == 401
        )


def test_collector_sensor_cannot_forge_another_asset(collector):
    _, client = collector
    assert (
        client.post(
            "/events",
            headers=sensor("asset-a"),
            json={
                "event_id": "forgery",
                "event_type": "asset_compromised",
                "actor": "red",
                "target_asset": "asset-b",
                "team_id": "bravo",
                "scenario_id": "exercise-a",
            },
        ).status_code
        == 404
    )
    assert client.get("/events", headers=sensor("asset-a")).status_code == 403


def test_reset_invalidates_signed_replay_cursors(collector):
    mod, client = collector
    populate(mod, [{}, {}])
    page = client.get("/replay/page?limit=1", headers=auth()).json()
    client.post(
        "/admin/reset",
        headers={"Authorization": "Bearer scope-test-instructor"},
        json={"confirm": True, "reason": "exercise reset"},
    )
    response = client.get(
        "/replay/page", params={"cursor": page["next_cursor"]}, headers=auth()
    )
    assert response.status_code == 409


def test_durable_sse_resume_and_role_projection(collector):
    from starlette.requests import Request

    mod, _ = collector
    populate(
        mod, [{}, {"actor": "blue"}, {"team_id": "bravo"}, {"event_id": "own-later"}]
    )

    async def read():
        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        req = Request(
            {
                "type": "http",
                "method": "GET",
                "path": "/stream",
                "headers": [],
                "state": {"range_authorization": "Bearer scope-test-instructor"},
            },
            receive,
        )
        marker = scope._current.set(
            Identity(
                actor="red-user", role="red", team_id="alpha", match_id="exercise-a"
            )
        )
        try:
            response = await mod.stream(
                req,
                last_event_id="1",
                authorization="Bearer scope-test-instructor",
                cr_token=None,
                last_event_id_hdr="",
            )
            iterator = response.body_iterator
            assert await anext(iterator) == "retry: 3000\n\n"
            frame = await anext(iterator)
            await iterator.aclose()
            assert "own-later" in frame and "private" in frame
            assert "id: 4\n" in frame
        finally:
            scope._current.reset(marker)

    asyncio.run(read())


def test_score_views_scope_before_aggregation(monkeypatch, tmp_path):
    from services.scoring_engine import main as mod

    monkeypatch.setattr(mod, "DB_PATH", tmp_path / "scores.db")
    mod.init_db()
    conn = mod.get_db()
    for team, scenario, actor, score in [
        ("alpha", "exercise-a", "red", 10),
        ("alpha", "exercise-a", "blue", 20),
        ("bravo", "exercise-a", "red", 99),
        ("alpha", "exercise-b", "blue", 88),
    ]:
        conn.execute(
            "INSERT INTO team_scores(team_id,scenario_id,actor,score) VALUES(?,?,?,?)",
            (team, scenario, actor, score),
        )
    conn.commit()
    conn.close()
    client = TestClient(mod.app)
    assert client.get("/scores", headers=auth()).json()["teams"] == {
        "alpha": {"red": 10, "blue": 20}
    }
    assert client.get("/scores", headers=auth("red")).json()["teams"] == {
        "alpha": {"red": 10}
    }
    assert (
        client.get("/scores?scenario_id=exercise-b", headers=auth()).status_code == 403
    )


def test_portal_closes_admin_audit_and_cross_exercise_claims(monkeypatch):
    from services.challenge_portal import main as mod

    client = TestClient(mod.app)
    assert client.post("/portal/admin/reset").status_code == 401
    assert client.get("/portal/anticheat/audit", headers=auth("red")).status_code == 403
    assert client.get("/portal/blue/challenges", headers=auth("red")).status_code == 403
    assert (
        client.get("/portal/challenges?team_id=bravo", headers=auth("red")).status_code
        == 403
    )
    marker = scope._current.set(
        Identity(actor="real-user", role="red", team_id="alpha", match_id="exercise-a")
    )
    try:
        assert mod._submitter_subject("", "forged-user") == "real-user"
        assert mod._effective_team("alpha", None) == "exercise-a::alpha"
        with pytest.raises(HTTPException):
            mod._effective_team("alpha", "exercise-b")
    finally:
        scope._current.reset(marker)


_verify_session = scope.verify_session


@pytest.mark.parametrize("upstream,expected", [(200, None), (401, 401), (503, 503)])
def test_revocation_verification_fails_closed_on_auth_errors(
    monkeypatch, upstream, expected
):
    original = httpx.AsyncClient
    calls = []

    def handle(request):
        calls.append(request)
        return httpx.Response(upstream, json={"actor": "test"})

    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kw: original(transport=httpx.MockTransport(handle), **kw),
    )
    if expected:
        with pytest.raises(HTTPException) as exc:
            asyncio.run(_verify_session("Bearer header.payload.signature"))
        assert exc.value.status_code == expected
    else:
        asyncio.run(_verify_session("Bearer header.payload.signature"))
    assert calls[0].url.path == "/auth/me"
    assert calls[0].headers["Authorization"] == "Bearer header.payload.signature"


def test_idle_socket_is_closed_when_session_is_revoked(monkeypatch):
    async def revoked(_):
        raise HTTPException(401, "revoked")

    monkeypatch.setattr(scope, "verify_session", revoked)
    # No wall-clock waiting: advance the scheduled verification deadline.
    times = iter([0, 16])
    monkeypatch.setattr(scope.time, "monotonic", lambda: next(times, 16))

    class Socket:
        scope = {"state": {"range_authorization": "Bearer header.payload.signature"}}
        code = None

        async def close(self, code):
            self.code = code

    ws = Socket()
    # time.monotonic is shared with asyncio: run the coroutine directly until completion.
    coro = scope.receive_while_authorized(ws)
    with pytest.raises(StopIteration):
        coro.send(None)
    assert ws.code == 4401


def test_replay_pages_cover_more_than_fifty_thousand_events(collector):
    mod, client = collector
    count = 50003
    populate(
        mod,
        [{"event_id": f"volume-{i:06}", "timestamp": 100 + i} for i in range(count)],
    )
    cursor = ""
    seen = []
    while True:
        result = client.get(
            "/replay/page", params={"limit": 5000, "cursor": cursor}, headers=auth()
        ).json()
        seen.extend(e["event_id"] for e in result["events"])
        cursor = result["next_cursor"]
        if not cursor:
            break
    assert len(seen) == count and len(set(seen)) == count
    assert seen[-1] == "volume-050002"


def test_personal_contribution_does_not_mix_the_same_team_across_exercises():
    from shared.assessment import team_contribution

    solves = {
        "exercise-a::alpha": {"one": {"points": 10, "by": "alice"}},
        "exercise-b::alpha": {"two": {"points": 100, "by": "bob"}},
    }
    result = team_contribution(solves, "exercise-a::alpha")
    assert result["total_points"] == 10
    assert [r["subject"] for r in result["members"]] == ["alice"]


def test_paired_red_blue_ownership_preserves_the_actor_scoring_team(
    collector, monkeypatch
):
    mod, client = collector
    monkeypatch.setenv(
        "RANGE_ASSET_SCOPES",
        json.dumps(
            {
                "asset-a": {
                    "team_id": "alpha",
                    "red_team_id": "red-alpha",
                    "scenario_id": "exercise-a",
                }
            }
        ),
    )

    async def forwarded(_):
        pass

    monkeypatch.setattr(mod, "_forward_to_scoring_engine", forwarded)
    with client:
        r = client.post(
            "/events",
            headers=sensor("asset-a"),
            json={
                "event_id": "paired",
                "event_type": "asset_compromised",
                "actor": "red",
                "target_asset": "asset-a",
                "team_id": "forged",
                "scenario_id": "forged",
            },
        )
        assert r.status_code == 200, r.text
        red = client.get("/events", headers=auth("red", team="red-alpha")).json()[
            "events"
        ]
        blue = client.get("/events", headers=auth()).json()["events"]
        assert len(red) == len(blue) == 1
        assert red[0]["team_id"] == "red-alpha"
        assert red[0]["defender_team_id"] == "alpha"
        assert (
            client.get("/events", headers=auth("red", team="alpha")).json()["events"]
            == []
        )


def test_live_stream_announces_reset_without_requiring_reconnect(collector):
    from starlette.requests import Request

    mod, _ = collector
    populate(mod, [{}])

    async def read():
        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        req = Request(
            {
                "type": "http",
                "method": "GET",
                "path": "/stream",
                "headers": [],
                "state": {},
            },
            receive,
        )
        marker = scope._current.set(Identity(actor="instructor", role="instructor"))
        try:
            response = await mod.stream(
                req,
                authorization="Bearer scope-test-instructor",
                cr_token=None,
                last_event_id_hdr="",
            )
            iterator = response.body_iterator
            await anext(iterator)
            assert "asset_compromised" in await anext(iterator)
            mod.admin_reset(authorization="Bearer scope-test-instructor")
            assert "event: stream-gap" in await asyncio.wait_for(
                anext(iterator), timeout=2
            )
            await iterator.aclose()
        finally:
            scope._current.reset(marker)

    asyncio.run(read())


def test_batch_failure_rolls_back_event_and_journal_together(collector, monkeypatch):
    from shared.event_schema import Event
    from services.event_collector import journal

    mod, _ = collector
    append = journal.append

    def failure(conn, topic, data, event_id=None):
        if event_id == "second":
            raise OSError("simulated storage failure")
        return append(conn, topic, data, event_id)

    monkeypatch.setattr(journal, "append", failure)
    records = [
        Event(
            event_id=eid,
            event_type="asset_compromised",
            actor="red",
            target_asset="asset-a",
        )
        for eid in ("first", "second")
    ]
    with pytest.raises(OSError):
        mod._persist_batch(records)
    conn = mod.get_db()
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM stream_journal").fetchone()[0] == 0
    assert mod._writer_conn.in_transaction is False
    conn.close()


@pytest.mark.parametrize(
    "service,path,method",
    [
        ("edr", "/edr/hosts/asset-a/admin-peek", "GET"),
        ("incident", "/incidents/export-everyone", "POST"),
        ("portal", "/portal/blue/admin-reset", "POST"),
        ("scenario", "/scenario/secret/progress", "DELETE"),
    ],
)
def test_new_route_prefixes_do_not_implicitly_grant_team_authority(
    service, path, method
):
    assert scope.human_roles(service, path, method) == {"instructor"}
