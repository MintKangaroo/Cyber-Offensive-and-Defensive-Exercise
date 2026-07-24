"""
ICS 트윈 팩토리 유닛 테스트 (shared/ics_twin.py)
================================================
8개 ICS/OT 섹터 트윈을 만들어내는 make_ics_twin 팩토리의 핵심 계약을 검증:
  - 취약(dev/unpatched): 200 + emit 호출
  - 패치(PATCH_<ID>=true): 핸들러가 deny(status) → 해당 상태코드
  - payload 병합: GET query + POST json body가 핸들러에 함께 전달
  - health 엔드포인트

emit_event/start_edr_agent는 네트워크 의존이라 no-op로 대체(테스트 격리·속도).
"""
import pytest
from fastapi.testclient import TestClient

from shared import ics_twin
from shared.ics_twin import make_ics_twin, Vuln, deny


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    # 네트워크 의존 제거
    calls = []
    monkeypatch.setattr(ics_twin, "emit_event", lambda **kw: calls.append(kw))
    monkeypatch.setattr(ics_twin, "start_edr_agent", lambda asset_name: None)
    # 패치 env 초기화
    for k in ("PATCH_TST_001", "PATCH_TST_002"):
        monkeypatch.delenv(k, raising=False)
    return calls


def _read_handler(patched, payload, emit):
    if patched:
        deny(401, "auth required")
    emit({"node": payload.get("node")})
    return {"value": 42, "echo": payload.get("node")}


def _write_handler(patched, payload, emit):
    if patched and payload.get("key") != "ok":
        deny(403, "need key")
    emit({"addr": payload.get("addr")})
    return {"written": payload.get("addr"), "value": payload.get("value")}


def _build():
    vulns = [
        Vuln("TST-001", "/api/read", "GET", "read", "red_attack_started", "initial_access", _read_handler),
        Vuln("TST-002", "/api/write", "POST", "write", "red_objective_success", "objective", _write_handler),
    ]
    return make_ics_twin("test_twin", "Test Twin", vulns)


def test_health():
    c = TestClient(_build())
    r = c.get("/health")
    assert r.status_code == 200 and r.json()["service"] == "test_twin"


def test_vulnerable_get_emits(_isolate):
    c = TestClient(_build())
    r = c.get("/api/read", params={"node": "ns=2;s=X"})
    assert r.status_code == 200
    assert r.json()["echo"] == "ns=2;s=X"
    assert r.json()["patched"] is False
    # emit 호출됨(취약 경로)
    assert any(e["vuln_id"] == "TST-001" for e in _isolate)


def test_patched_get_denies(monkeypatch):
    monkeypatch.setenv("PATCH_TST_001", "true")
    c = TestClient(_build())
    r = c.get("/api/read", params={"node": "x"})
    assert r.status_code == 401


def test_post_payload_merge(_isolate):
    c = TestClient(_build())
    r = c.post("/api/write", json={"addr": 40001, "value": 0})
    assert r.status_code == 200
    assert r.json()["written"] == 40001
    assert any(e["vuln_id"] == "TST-002" for e in _isolate)


def test_patched_post_denies_without_key(monkeypatch):
    monkeypatch.setenv("PATCH_TST_002", "true")
    c = TestClient(_build())
    assert c.post("/api/write", json={"addr": 1}).status_code == 403
    # 올바른 키면 통과
    assert c.post("/api/write", json={"addr": 1, "key": "ok"}).status_code == 200


def test_team_header_propagates(_isolate):
    c = TestClient(_build())
    c.get("/api/read", params={"node": "x"}, headers={"X-Team-Id": "teamZ"})
    assert any(e.get("team_id") == "teamZ" for e in _isolate)
