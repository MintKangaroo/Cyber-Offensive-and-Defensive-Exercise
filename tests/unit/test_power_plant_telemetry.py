"""발전소 트윈 읽기전용 텔레메트리 엔드포인트 + 훈련 콘솔 CORS 회귀 테스트.

livefire-ops 작전 콘솔이 /api/telemetry 를 폴링해 라이브 게이지를 그리고,
브라우저(localhost 오리진)에서 공격/관측을 구동한다. 이 두 계약을 고정한다.
"""
from fastapi.testclient import TestClient

from services.power_plant import main as pp

client = TestClient(pp.app)

TELEMETRY_KEYS = {
    "cmd_rpm", "coolant_flow", "actual_rpm", "coolant_temp", "damage", "interlock", "failed",
}


def test_telemetry_exposes_live_physics_fields():
    r = client.get("/api/telemetry")
    assert r.status_code == 200
    body = r.json()
    assert set(body) == TELEMETRY_KEYS
    # 수치 필드는 정수, 상태 필드는 bool
    for k in ("cmd_rpm", "coolant_flow", "actual_rpm", "coolant_temp", "damage"):
        assert isinstance(body[k], int)
    assert isinstance(body["interlock"], bool)
    assert isinstance(body["failed"], bool)


def test_telemetry_reports_nominal_at_rest():
    """기동 직후(프로세스 루프 미동작)엔 공칭 상태: 인터록 ARMED, 손상/파국 없음."""
    body = client.get("/api/telemetry").json()
    assert body["interlock"] is True
    assert body["damage"] == 0
    assert body["failed"] is False
    assert body["actual_rpm"] == 3000  # ProcessState 초기값(공칭 RPM)


def test_console_origin_gets_cors_header():
    """localhost 오리진(훈련 콘솔)에 CORS 허용 헤더가 반환된다."""
    origin = "http://localhost:5177"
    r = client.get("/api/telemetry", headers={"Origin": origin})
    assert r.status_code == 200
    assert r.headers.get("access-control-allow-origin") == origin


def test_safety_override_reaches_live_telemetry():
    """콘솔 EXECUTE(POST /api/safety/override) → /api/telemetry 인터록이 실제로 BYPASS 된다.
    (HTTP 공격이 Modbus 뱅크/물리에 반영되는 일관성 — '공격하면 게이지가 움직인다'의 전제.)"""
    try:
        assert client.get("/api/telemetry").json()["interlock"] is True
        r = client.post("/api/safety/override", json={"override": True})
        assert r.status_code == 200
        assert client.get("/api/telemetry").json()["interlock"] is False
    finally:
        client.post("/api/safety/override", json={"override": False})  # 상태 복원(재무장)
    assert client.get("/api/telemetry").json()["interlock"] is True


def test_cors_preflight_allowed_for_attack_post():
    """콘솔의 EXECUTE STRIKE(POST /api/safety/override) 프리플라이트가 허용된다."""
    r = client.options(
        "/api/safety/override",
        headers={
            "Origin": "http://localhost:5177",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert r.status_code in (200, 204)
    assert r.headers.get("access-control-allow-origin") == "http://localhost:5177"
