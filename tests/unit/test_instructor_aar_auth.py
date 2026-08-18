"""
instructor_api · aar_report 인증 계약 (감사 1.8)
================================================
두 서비스의 전 엔드포인트(health 제외)가 무토큰 요청을 401로 거부하는지 못박는다.
과거 /instructor/audit·/report/aar·/report/aar/pdf 는 무인증 노출이었다(감사 S-2 계열).

토큰이 하나도 없고 RBAC_ALLOW_INSECURE_DEV 도 없으면 rbac 는 fail-closed(401)이어야 한다.
"""
import importlib

import pytest
from fastapi.testclient import TestClient

_AUTH_ENVS = ["INSTRUCTOR_TOKEN", "RED_TOKEN", "BLUE_TOKEN", "OBSERVER_TOKEN",
              "RBAC_TOKENS", "AUTH_JWT_SECRET", "RBAC_ALLOW_INSECURE_DEV"]


@pytest.fixture
def _no_auth_env(monkeypatch):
    for k in _AUTH_ENVS:
        monkeypatch.delenv(k, raising=False)
    yield


@pytest.fixture
def instructor_client(_no_auth_env):
    import services.instructor_api.main as m
    importlib.reload(m)
    return TestClient(m.app), m


@pytest.fixture
def aar_client(_no_auth_env):
    import services.aar_report.main as m
    importlib.reload(m)
    return TestClient(m.app)


# --- instructor_api ---------------------------------------------------------

def test_instructor_health_open(instructor_client):
    client, _ = instructor_client
    assert client.get("/health").status_code == 200


def test_instructor_audit_requires_auth(instructor_client):
    client, _ = instructor_client
    # 과거 무인증이던 감사 로그 조회 → 이제 401.
    assert client.get("/instructor/audit").status_code == 401


@pytest.mark.parametrize("method,path,body", [
    ("post", "/instructor/scenario/start", {"scenario_id": "s", "reason": "r"}),
    ("post", "/instructor/scenario/end", {"scenario_id": "s", "reason": "r"}),
    ("post", "/instructor/event/inject",
     {"event_type": "x", "target_asset": "a", "reason": "r"}),
    ("post", "/instructor/score/adjust",
     {"team_id": "t", "actor": "a", "delta": 1, "reason": "r"}),
])
def test_instructor_writes_require_auth(instructor_client, method, path, body):
    client, _ = instructor_client
    r = getattr(client, method)(path, json=body)
    assert r.status_code == 401


def test_instructor_audit_ok_with_token(monkeypatch):
    monkeypatch.setenv("INSTRUCTOR_TOKEN", "itok")
    for k in ("RED_TOKEN", "BLUE_TOKEN", "OBSERVER_TOKEN", "RBAC_TOKENS",
              "AUTH_JWT_SECRET", "RBAC_ALLOW_INSECURE_DEV"):
        monkeypatch.delenv(k, raising=False)
    import services.instructor_api.main as m
    importlib.reload(m)
    client = TestClient(m.app)
    r = client.get("/instructor/audit", headers={"Authorization": "Bearer itok"})
    assert r.status_code == 200 and "entries" in r.json()


# --- aar_report -------------------------------------------------------------

def test_aar_health_open(aar_client):
    assert aar_client.get("/health").status_code == 200


@pytest.mark.parametrize("path", ["/report/aar", "/report/aar/pdf"])
def test_aar_requires_auth(aar_client, path):
    assert aar_client.get(path).status_code == 401
