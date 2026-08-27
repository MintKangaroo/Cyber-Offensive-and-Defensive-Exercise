"""
감사 §3 G-11: 네트워크 계층 배경 트래픽 유닛 테스트.

순수 로직(profile) + 드라이버 집계(driver) + ground truth 라벨 전파(parser/AAR)를 검증한다.
실 HTTP·도커 없이: 드라이버는 가짜 클라이언트를 주입해 네트워크 없이 집계를 확인한다.
"""
from __future__ import annotations

import asyncio
import random
from datetime import datetime

import pytest

from services.traffic_generator.profile import (
    BENIGN_CATALOG,
    TWIN_PORTS,
    INTERNAL_USER_BAND,
    TrafficProfile,
    business_hours_weight,
    plan_request,
)
from services.traffic_generator.driver import TrafficDriver, BACKGROUND_HEADERS_BASE


# route_vuln_map에 매핑된 경로(=배경 트래픽에 절대 쓰면 안 되는 취약점 경로).
# 이 경로들은 status<400이어도 파서가 severity 3으로 올려 clean noise가 아니게 된다.
_VULN_MAPPED = {
    "ground_station": {"/api/telemetry", "/api/login", "/api/mission-plan", "/api/download",
                       "/api/debug/config", "/api/tle/import", "/api/config/xml-import"},
    "power_plant": {"/api/plc/write", "/api/hmi/login", "/api/diagnostics/ping",
                    "/api/historian/export", "/api/safety/override",
                    "/api/modbus/write-register", "/api/plc/firmware-update"},
    "defense_network": {"/api/smb/shares", "/api/ad/service-accounts",
                        "/api/fileserver/backup-config", "/api/mail/relay",
                        "/api/directory/search", "/api/webhook/preview"},
}


def test_business_hours_weight():
    assert business_hours_weight(datetime(2026, 8, 27, 10, 0)) == 1.0   # 업무시간
    assert business_hours_weight(datetime(2026, 8, 27, 3, 0)) == 0.3    # 새벽
    assert business_hours_weight(datetime(2026, 8, 27, 18, 0)) == 0.3   # 18시 경계(제외)


def test_effective_eps_and_interval():
    p = TrafficProfile(base_eps=2.0)
    day = datetime(2026, 8, 27, 12, 0)
    night = datetime(2026, 8, 27, 2, 0)
    assert p.effective_eps(day) == 2.0
    assert p.effective_eps(night) == pytest.approx(0.6)
    assert p.interval_seconds(day) == pytest.approx(0.5)
    # 최소 0.1 eps 보장(무한대 간격 방지)
    assert TrafficProfile(base_eps=0.0).effective_eps(day) == 0.1


def test_enabled_assets_covers_all_twins_with_ports():
    p = TrafficProfile()
    assert set(p.enabled_assets()) == set(TWIN_PORTS)


def test_catalog_is_benign_only():
    """카탈로그의 모든 경로는 vuln-map에 없어야 한다(clean noise 불변식)."""
    for asset, endpoints in BENIGN_CATALOG.items():
        for ep in endpoints:
            assert ep.path not in _VULN_MAPPED.get(asset, set()), (
                f"{asset}{ep.path} 는 vuln-map된 경로 — 배경 트래픽에 쓰면 안 됨")
        # 모든 트윈은 최소 /health(양성 하트비트)를 가진다.
        assert any(e.path == "/health" for e in endpoints)


def test_plan_request_is_valid_and_deterministic():
    p = TrafficProfile()
    rng = random.Random(42)
    req = plan_request(p, rng)
    assert req is not None
    assert req.asset in TWIN_PORTS
    assert req.port == TWIN_PORTS[req.asset]
    assert req.src_ip in INTERNAL_USER_BAND
    assert req.url == f"http://{req.asset}:{req.port}{req.path}"
    # 같은 시드는 같은 계획(재현성)
    assert plan_request(p, random.Random(42)) == req


def test_plan_request_none_when_no_assets():
    p = TrafficProfile(assets=[])
    assert plan_request(p, random.Random(1)) is None


def test_asset_scoping_limits_targets():
    """BACKGROUND_TRAFFIC_ASSETS 스코프: 지정한 트윈만 겨냥한다."""
    p = TrafficProfile(assets=["power_plant"])
    assert p.enabled_assets() == ["power_plant"]
    for _ in range(50):
        req = plan_request(p, random.Random())
        assert req.asset == "power_plant"
    # 알 수 없는 자산은 걸러진다(포트/카탈로그 없음).
    assert TrafficProfile(assets=["power_plant", "nonexistent"]).enabled_assets() == ["power_plant"]


def test_plan_request_only_hits_benign_paths():
    p = TrafficProfile()
    rng = random.Random(7)
    for _ in range(200):
        req = plan_request(p, rng)
        assert req.path not in _VULN_MAPPED.get(req.asset, set())


class _FakeResponse:
    def __init__(self, status_code: int):
        self.status_code = status_code


class _FakeClient:
    """httpx.AsyncClient 대체: 네트워크 없이 헤더/호출을 기록한다."""
    def __init__(self):
        self.calls: list[tuple[str, str, dict]] = []

    async def get(self, url, headers=None):
        self.calls.append(("GET", url, headers or {}))
        return _FakeResponse(200)

    async def post(self, url, json=None, headers=None):
        self.calls.append(("POST", url, headers or {}))
        return _FakeResponse(200)

    async def aclose(self):
        pass


def test_driver_send_one_labels_and_counts():
    async def _run():
        p = TrafficProfile()
        d = TrafficDriver(p, rng=random.Random(3))
        fake = _FakeClient()
        d._client = fake
        from services.traffic_generator.profile import plan_request as pr
        req = pr(p, random.Random(3))
        await d._send_one(req)
        # 집계
        assert d.stats.sent == 1
        assert d.stats.errors == 0
        assert d.stats.by_asset.get(req.asset) == 1
        assert d.stats.last_status == 200
        # 배경 라벨 헤더가 반드시 붙는다(ground truth)
        _, url, headers = fake.calls[0]
        assert headers["X-Background-Traffic"] == "1"
        assert headers["X-Forwarded-For"] == req.src_ip
        assert headers["X-Team-Id"] == "noise"
        assert "background" in headers["User-Agent"].lower()
    asyncio.run(_run())


def test_driver_counts_errors_on_failure():
    class _BrokenClient(_FakeClient):
        async def get(self, url, headers=None):
            raise OSError("connection refused")

    async def _run():
        p = TrafficProfile()
        d = TrafficDriver(p, rng=random.Random(5))
        d._client = _BrokenClient()
        req = plan_request(p, random.Random(5))
        await d._send_one(req)
        assert d.stats.sent == 0
        assert d.stats.errors == 1
    asyncio.run(_run())


def test_background_headers_base_are_labeled():
    assert BACKGROUND_HEADERS_BASE["X-Background-Traffic"] == "1"
    assert BACKGROUND_HEADERS_BASE["X-Team-Id"] == "noise"


def test_service_module_imports():
    """import 스모크: uvicorn이 `services.traffic_generator.main`으로 로드하는 경로를
    유닛에서 재현한다. main이 driver/profile을 잘못 import하면(예: bare import로 driver의
    상대 import와 충돌) 여기서 잡힌다 — 유닛이 main을 안 열면 integration까지 못 잡는다."""
    import importlib
    m = importlib.import_module("services.traffic_generator.main")
    assert m.app.title.startswith("Background Traffic Generator")
    assert hasattr(m, "_driver") and hasattr(m, "_profile")


# --- ground truth 라벨이 파서를 통해 전파되는가 (감사 G-11) -------------------

def test_parser_propagates_background_label():
    """미들웨어가 찍은 is_background가 파서에서 raw 보존 + 태그로 노출된다."""
    import json as _json
    from services.siem.parsers.twin import parse_twin_log_line

    bg_line = _json.dumps({
        "ts": 1000.0, "asset": "power_plant", "endpoint": "/health",
        "method": "GET", "status": 200, "src_ip": "10.50.0.11",
        "team_id": "noise", "is_background": True,
    })
    ev = parse_twin_log_line(bg_line)
    assert ev is not None
    assert ev.raw.get("is_background") is True
    assert "background_traffic" in ev.tags
    assert ev.severity == 0  # 양성(비-vuln 200) = clean noise

    # 배경 라벨이 없으면 태그도 없다(일반 트래픽/공격).
    normal_line = _json.dumps({
        "ts": 1000.0, "asset": "power_plant", "endpoint": "/health",
        "method": "GET", "status": 200, "src_ip": "10.9.9.9", "team_id": "red",
    })
    ev2 = parse_twin_log_line(normal_line)
    assert ev2 is not None
    assert "background_traffic" not in ev2.tags
