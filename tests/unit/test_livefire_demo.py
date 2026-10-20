"""Live Fire 데모 오케스트레이터 회귀 — 활성→킬체인→비활성 순서/멱등/중단을 네트워크 없이 검증."""
from __future__ import annotations

import pytest

from scripts.demo import livefire_demo as D


class _Resp:
    def __init__(self, status_code: int):
        self.status_code = status_code


class FakeHttp:
    """.post/.get 호출을 순서대로 기록하고, URL 접미사별로 상태코드를 돌려주는 가짜 클라이언트."""

    def __init__(self, status_by_suffix: dict[str, int] | None = None, default: int = 200):
        self.calls: list[tuple[str, str, dict]] = []  # (method, url, json)
        self._status = status_by_suffix or {}
        self._default = default

    def _status_for(self, url: str) -> int:
        for suffix, code in self._status.items():
            if url.endswith(suffix):
                return code
        return self._default

    def post(self, url, *, json, headers, timeout):
        self.calls.append(("POST", url, json))
        return _Resp(self._status_for(url))

    def get(self, url, *, headers, timeout):
        self.calls.append(("GET", url, {}))
        return _Resp(self._status_for(url))


def _plan():
    return D.SECTOR_PLANS["power"]


def test_full_sequence_activate_then_killchain_then_deactivate():
    http = FakeHttp()
    res = D.run_demo(_plan(), http, hold_sec=0, step_pause=0, sleep=lambda _s: None, on_log=lambda _m: None)

    assert res.activated is True and res.deactivated is True
    # 활성 → 4단계 → 비활성, 정확히 이 순서.
    assert http.calls[0][1].endswith("/scenario/activate")
    assert http.calls[-1][1].endswith("/scenario/deactivate")
    # 가운데 4건이 킬체인(트윈 공격 엔드포인트).
    mid = http.calls[1:-1]
    assert len(mid) == 4
    assert [c[1].split("/api/")[1] for c in mid] == [
        "hmi/login", "plc/write", "plc/write", "safety/override",
    ]
    assert res.steps_driven == [s.label for s in _plan().steps]
    assert res.step_status == [200, 200, 200, 200]


def test_no_attack_only_activates_timers():
    http = FakeHttp()
    res = D.run_demo(_plan(), http, hold_sec=0, drive_attack=False, sleep=lambda _s: None, on_log=lambda _m: None)
    assert res.activated and res.deactivated
    assert res.steps_driven == []
    # activate + deactivate 만 — 트윈 공격 호출 없음.
    assert [c[1].split("/")[-1] for c in http.calls] == ["activate", "deactivate"]


def test_already_active_409_is_idempotent():
    http = FakeHttp(status_by_suffix={"/scenario/activate": 409})
    res = D.run_demo(_plan(), http, hold_sec=0, step_pause=0, sleep=lambda _s: None, on_log=lambda _m: None)
    assert res.activated is True
    assert any("already active" in n for n in res.notes)
    assert res.steps_driven == [s.label for s in _plan().steps]  # 멱등이므로 킬체인은 계속 구동


def test_activate_failure_aborts_without_driving_or_deactivating():
    http = FakeHttp(status_by_suffix={"/scenario/activate": 500})
    res = D.run_demo(_plan(), http, hold_sec=0, step_pause=0, sleep=lambda _s: None, on_log=lambda _m: None)
    assert res.activated is False
    assert res.steps_driven == []          # 타이머가 안 흐르므로 킬체인 구동 안 함
    assert res.deactivated is False
    assert len(http.calls) == 1            # activate 한 번만 시도
    assert any("activate failed" in n for n in res.notes)


def test_deactivate_404_counts_as_clean():
    http = FakeHttp(status_by_suffix={"/scenario/deactivate": 404})
    res = D.run_demo(_plan(), http, hold_sec=0, step_pause=0, sleep=lambda _s: None, on_log=lambda _m: None)
    assert res.deactivated is True  # 이미 비활성(404) = 정리 완료로 간주


def test_twin_unreachable_is_recorded_not_fatal():
    class Boom(FakeHttp):
        def post(self, url, *, json, headers, timeout):
            if "/api/" in url:
                raise ConnectionError("twin down")
            return super().post(url, json=json, headers=headers, timeout=timeout)

    http = Boom()
    res = D.run_demo(_plan(), http, hold_sec=0, step_pause=0, sleep=lambda _s: None, on_log=lambda _m: None)
    assert res.activated and res.deactivated          # 활성/비활성은 성공
    assert res.step_status == [0, 0, 0, 0]            # 트윈 미도달 → status 0
    assert any("unreachable" in n for n in res.notes)


def test_dry_run_plan_matches_power_endpoints():
    lines: list[str] = []
    D.print_plan(_plan(), on_log=lines.append)
    joined = "\n".join(lines)
    assert "/scenario/activate" in joined and "/scenario/deactivate" in joined
    assert "/api/hmi/login" in joined and "/api/safety/override" in joined


def test_main_dry_run_returns_zero(capsys):
    rc = D.main(["--sector", "power", "--dry-run"])
    assert rc == 0
    assert "dry-run" in capsys.readouterr().out
