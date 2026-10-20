"""ICS 트윈 공유 팩토리(make_ics_twin) CORS 회귀 테스트.

livefire-ops 작전 콘솔이 발전소뿐 아니라 병원·상수도 등 factory 기반 섹터 트윈도
브라우저에서 라이브로 공격 구동할 수 있어야 한다. make_ics_twin 에 추가한 CORS 를
대표 트윈 2개(hospital_ot·water_utility)로 고정한다.
"""
import pytest
from fastapi.testclient import TestClient

from services.hospital_ot import main as hospital
from services.water_utility import main as water

ORIGIN = "http://localhost:5177"

CASES = [
    (hospital.app, "/api/device/infusion"),  # HSP-003 주입펌프(POST)
    (water.app, "/api/dosing/chlorine"),      # WTR-001 염소 투입(POST)
]


@pytest.mark.parametrize("app,_path", CASES)
def test_console_origin_gets_cors_header(app, _path):
    client = TestClient(app)
    r = client.get("/health", headers={"Origin": ORIGIN})
    assert r.status_code == 200
    assert r.headers.get("access-control-allow-origin") == ORIGIN


@pytest.mark.parametrize("app,path", CASES)
def test_cors_preflight_allowed_for_attack_post(app, path):
    client = TestClient(app)
    r = client.options(
        path,
        headers={
            "Origin": ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert r.status_code in (200, 204)
    assert r.headers.get("access-control-allow-origin") == ORIGIN
