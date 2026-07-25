"""
섹터별 blue 자동 패치검증(shared/safe_probe.py) 유닛 테스트
========================================================
- 레지스트리가 11섹터·44취약점을 유니크하게 커버하는지
- _sector_check 분류(응답코드==patched_status → PATCHED, 아니면 VULNERABLE)
- run(asset=...) 섹터 스코프 필터 + 요약 집계
- emit 억제(--no-emit): blue_patch_verified(Event Collector /events POST) 미발행

네트워크 의존은 safe_probe.requests 모킹으로 제거(트윈/Event Collector 없이 동작).
"""
import types

import pytest

from shared import safe_probe


class _Resp:
    def __init__(self, status=401, payload=None):
        self.status_code = status
        self._payload = payload if payload is not None else {}

    def json(self):
        return self._payload


@pytest.fixture
def mock_requests(monkeypatch):
    """requests.get/post를 캡처. status/json은 라우팅별로 지정 가능.
    post 중 Event Collector(/events)로 간 건 emit로 간주해 따로 집계."""
    calls = {"get": [], "post": [], "emit_posts": []}
    status_holder = {"status": 401, "json": {}}

    def fake_get(url, **kw):
        calls["get"].append(url)
        return _Resp(status_holder["status"], status_holder["json"])

    def fake_post(url, **kw):
        calls["post"].append(url)
        if "/events" in url:
            calls["emit_posts"].append(url)
            return _Resp(200, {})
        return _Resp(status_holder["status"], status_holder["json"])

    fake_exc = types.SimpleNamespace(
        RequestException=safe_probe.requests.exceptions.RequestException,
        ConnectionError=safe_probe.requests.exceptions.ConnectionError,
    )
    monkeypatch.setattr(safe_probe.requests, "get", fake_get)
    monkeypatch.setattr(safe_probe.requests, "post", fake_post)
    monkeypatch.setattr(safe_probe.requests, "exceptions", fake_exc)
    return calls, status_holder


def test_registry_covers_all_unique_vulns():
    total = sum(len(v) for v in safe_probe.CHECKS_BY_ASSET.values())
    assert total == 60, f"체크 수 {total} ≠ 60"
    # 11섹터 전부 존재
    assert set(safe_probe.ASSET_ORDER) <= set(safe_probe.CHECKS_BY_ASSET)
    assert len(safe_probe.ASSET_ORDER) == 11


def test_sector_probe_specs_unique_ids():
    ids = [spec[5] for spec in safe_probe.SECTOR_PROBES]
    assert len(ids) == len(set(ids)) == 40


def test_sector_check_classifies_by_status(mock_requests):
    _, holder = mock_requests
    # refinery(5): REF-001(401 GET)·REF-003(401)·REF-004(401)=patched, REF-002(403)·REF-005(403)=vulnerable
    holder["status"] = 401
    out = safe_probe.run(asset="refinery_plant", emit=False)
    s = out["summary"]
    assert s["total"] == 5
    assert s["patched"] == 3 and s["vulnerable"] == 2
    assert s["by_asset"]["refinery_plant"] == {"patched": 3, "total": 5}


def test_asset_filter_scopes_single_sector(mock_requests):
    out = safe_probe.run(asset="water_utility", emit=False)
    assert set(r["asset"] for r in out["results"]) == {"water_utility"}
    assert out["summary"]["total"] == 5


def test_emit_suppressed_with_no_emit(mock_requests):
    calls, holder = mock_requests
    holder["status"] = 401
    safe_probe.run(asset="refinery_plant", emit=False)
    assert calls["emit_posts"] == []  # blue_patch_verified 미발행


def test_emit_fires_when_enabled(mock_requests):
    calls, holder = mock_requests
    holder["status"] = 401  # REF-001·REF-003·REF-004 patched → 3건 발행
    safe_probe.run(asset="refinery_plant", emit=True)
    assert len(calls["emit_posts"]) == 3


def test_full_run_covers_all_assets(mock_requests):
    _, holder = mock_requests
    holder["status"] = 200
    holder["json"] = {"results": []}  # GS-001 등 200+빈결과 계열 patched 경로
    out = safe_probe.run(emit=False)
    assert out["summary"]["total"] == 60
    assert set(out["summary"]["by_asset"]) == set(safe_probe.ASSET_ORDER)


# --- watch(주기적 재검증 데몬) ---

@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    """watch 루프의 time.sleep을 no-op로(테스트가 실제로 안 자게)."""
    monkeypatch.setattr(safe_probe.time, "sleep", lambda *_: None)


def test_watch_runs_bounded_iterations(mock_requests):
    cycles = []
    n = safe_probe.watch(interval=0, asset="refinery_plant", emit=False,
                         iterations=3, on_cycle=lambda i, out, newly: cycles.append(i))
    assert n == 3 and cycles == [1, 2, 3]


def test_watch_reports_newly_patched_delta(mock_requests):
    """1사이클: 미패치(REF-002 403 아님) → 2사이클: 패치 반영 시 신규패치 델타 보고."""
    _, holder = mock_requests
    seen = []

    # 사이클마다 응답 상태를 바꿔 패치 전이 시뮬레이션.
    holder["status"] = 200  # refinery 어느 것도 patched_status(401/403)와 불일치 → 전부 vulnerable

    def cb(i, out, newly):
        seen.append((i, sorted(newly), out["summary"]["patched"]))
        if i == 1:
            holder["status"] = 401  # 다음 사이클: REF-001·REF-003 patched로 전이

    safe_probe.watch(interval=0, asset="refinery_plant", emit=False, iterations=2, on_cycle=cb)
    assert seen[0][2] == 0                                  # 1사이클: 0 patched
    assert seen[1][2] == 3                                  # 2사이클: 3 patched(REF-001·003·004)
    assert seen[1][1] == ["REF-001", "REF-003", "REF-004"]  # 신규패치 델타로 보고
