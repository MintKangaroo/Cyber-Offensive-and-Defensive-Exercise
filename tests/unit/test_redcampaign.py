"""다팀 Red 캠페인 오케스트레이터 회귀 — 활성(중복제거·멱등)→동시 킬체인→비활성을 네트워크 없이 검증.

킬체인이 ThreadPoolExecutor 로 동시 구동되므로 FakeHttp 는 **스레드 안전**(call 기록에 lock)이다.
sleep=lambda _: None 로 실제 대기를 제거한다.
"""
from __future__ import annotations

import threading

import pytest

from scripts.demo import redcampaign as C


class _Resp:
    def __init__(self, status_code: int):
        self.status_code = status_code


class FakeHttp:
    """.post/.get 호출을 스레드 안전하게 기록하고 URL 접미사별 상태코드를 돌려주는 가짜 클라이언트."""

    def __init__(self, status_by_suffix: dict[str, int] | None = None, default: int = 200):
        self.calls: list[tuple[str, str, dict]] = []  # (method, url, json)
        self._status = status_by_suffix or {}
        self._default = default
        self._lock = threading.Lock()

    def _status_for(self, url: str) -> int:
        for suffix, code in self._status.items():
            if url.endswith(suffix):
                return code
        return self._default

    def post(self, url, *, json, headers, timeout):
        with self._lock:
            self.calls.append(("POST", url, json))
        return _Resp(self._status_for(url))

    def get(self, url, *, headers, timeout):
        with self._lock:
            self.calls.append(("GET", url, {}))
        return _Resp(self._status_for(url))

    # ── 질의 헬퍼 ──
    def activates(self) -> list[dict]:
        return [j for m, u, j in self.calls if u.endswith("/scenario/activate")]

    def deactivates(self) -> list[dict]:
        return [j for m, u, j in self.calls if u.endswith("/scenario/deactivate")]

    def twin_paths_for(self, base_contains: str) -> list[str]:
        """해당 트윈(base 식별 문자열)으로 간 공격 호출 경로를 순서대로."""
        return [u.split(base_contains, 1)[1] for m, u, j in self.calls
                if base_contains in u and "/api/" in u]


_NOSLEEP = lambda _s: None
_SILENT = lambda _m: None


def test_distinct_scenarios_activated_exactly_once():
    http = FakeHttp()
    engs = [
        C.Engagement("team-01", "power"),
        C.Engagement("team-02", "hospital"),
        C.Engagement("team-03", "water"),
    ]
    res = C.run_campaign(engs, http, hold_sec=0, step_pause=0, sleep=_NOSLEEP, on_log=_SILENT)

    acts = http.activates()
    sids = [a["scenario_id"] for a in acts]
    assert sorted(sids) == sorted({
        "POWERPLANT-MODBUS-SABOTAGE-01", "HOSPITAL-PHI-EXFIL-01", "WATER-POISON-01",
    })
    assert len(sids) == len(set(sids)) == 3  # 각 시나리오 정확히 1회 활성
    assert all(res.activated.values())


def test_shared_scenario_deduped_to_single_activate():
    http = FakeHttp()
    engs = [
        C.Engagement("team-01", "power"),
        C.Engagement("team-02", "power"),  # 같은 시나리오 공유
    ]
    res = C.run_campaign(engs, http, hold_sec=0, step_pause=0, sleep=_NOSLEEP, on_log=_SILENT)

    acts = http.activates()
    assert len(acts) == 1  # dedupe → 단 1회 활성
    # 활성 시 양 팀이 team_ids 에 모두 포함.
    assert acts[0]["team_ids"] == ["team-01", "team-02"]
    assert len(http.deactivates()) == 1  # 비활성도 1회
    # 두 교전 모두 킬체인은 구동됨.
    assert len(res.engagements) == 2
    assert all(len(er.steps_driven) == 4 for er in res.engagements)


def test_every_engagement_killchain_driven_in_order():
    http = FakeHttp()
    engs = [
        C.Engagement("team-01", "power"),
        C.Engagement("team-02", "hospital"),
        C.Engagement("team-03", "water"),
    ]
    C.run_campaign(engs, http, hold_sec=0, step_pause=0, sleep=_NOSLEEP, on_log=_SILENT)

    # 각 트윈 베이스로 간 공격 경로가 data.ts 체인 순서와 일치.
    assert http.twin_paths_for(":8002") == [
        "/api/hmi/login", "/api/plc/write", "/api/plc/write", "/api/safety/override",
    ]
    assert http.twin_paths_for(":8208") == [
        "/api/his/patient", "/api/pacs/study", "/api/device/infusion", "/api/safety/override",
    ]
    assert http.twin_paths_for(":8203") == [
        "/api/hmi/login", "/api/pump/control", "/api/dosing/chlorine", "/api/safety/override",
    ]


def test_all_distinct_scenarios_deactivated():
    http = FakeHttp()
    engs = [
        C.Engagement("team-01", "power"),
        C.Engagement("team-02", "hospital"),
    ]
    res = C.run_campaign(engs, http, hold_sec=0, step_pause=0, sleep=_NOSLEEP, on_log=_SILENT)

    deact_sids = {d["scenario_id"] for d in http.deactivates()}
    assert deact_sids == {"POWERPLANT-MODBUS-SABOTAGE-01", "HOSPITAL-PHI-EXFIL-01"}
    assert all(res.deactivated.values())


def test_activate_failure_skips_only_that_scenario_killchain():
    # power 활성 실패(500) → power 교전은 구동 생략, hospital 은 정상 구동.
    http = FakeHttp(status_by_suffix={})
    # power scenario activate 만 실패하도록: 시나리오 ID 접미사가 아니라 전체 /scenario/activate 가 공용이므로
    # 커스텀 상태 매핑을 쓴다.

    class _Sel(FakeHttp):
        def _status_for(self, url: str) -> int:
            return super()._status_for(url)

        def post(self, url, *, json, headers, timeout):
            with self._lock:
                self.calls.append(("POST", url, json))
            if url.endswith("/scenario/activate") and json.get("scenario_id") == "POWERPLANT-MODBUS-SABOTAGE-01":
                return _Resp(500)
            return _Resp(200)

    http = _Sel()
    engs = [
        C.Engagement("team-01", "power"),
        C.Engagement("team-02", "hospital"),
    ]
    res = C.run_campaign(engs, http, hold_sec=0, step_pause=0, sleep=_NOSLEEP, on_log=_SILENT)

    assert res.activated["POWERPLANT-MODBUS-SABOTAGE-01"] is False
    assert res.activated["HOSPITAL-PHI-EXFIL-01"] is True
    by_team = {er.team_id: er for er in res.engagements}
    assert by_team["team-01"].steps_driven == []  # 비활성 시나리오 → 킬체인 생략
    assert any("not active" in n for n in by_team["team-01"].notes)
    assert len(by_team["team-02"].steps_driven) == 4  # hospital 은 정상 구동
    assert any("activate" in n and "failed" in n for n in res.notes)
    # 두 시나리오 모두 비활성 호출됨(정리는 distinct 전체).
    assert {d["scenario_id"] for d in http.deactivates()} == {
        "POWERPLANT-MODBUS-SABOTAGE-01", "HOSPITAL-PHI-EXFIL-01",
    }


def test_already_active_409_is_idempotent():
    http = FakeHttp(status_by_suffix={"/scenario/activate": 409})
    engs = [C.Engagement("team-01", "power")]
    res = C.run_campaign(engs, http, hold_sec=0, step_pause=0, sleep=_NOSLEEP, on_log=_SILENT)
    assert res.activated["POWERPLANT-MODBUS-SABOTAGE-01"] is True
    assert any("already active" in n for n in res.notes)
    assert len(res.engagements[0].steps_driven) == 4  # 멱등 → 킬체인 계속 구동


def test_no_attack_only_activates_and_deactivates():
    http = FakeHttp()
    engs = [C.Engagement("team-01", "power")]
    C.run_campaign(engs, http, hold_sec=0, drive_attack=False, sleep=_NOSLEEP, on_log=_SILENT)
    # activate + deactivate 만, 트윈 공격 호출 없음.
    assert all("/api/" not in u for m, u, j in http.calls)
    assert len(http.activates()) == 1 and len(http.deactivates()) == 1


def test_dry_run_plan_lists_scenarios_and_steps():
    lines: list[str] = []
    engs = [
        C.Engagement("team-01", "power"),
        C.Engagement("team-02", "hospital"),
    ]
    C.print_plan(engs, on_log=lines.append)
    joined = "\n".join(lines)
    assert "dry-run" in joined
    assert "POWERPLANT-MODBUS-SABOTAGE-01" in joined and "HOSPITAL-PHI-EXFIL-01" in joined
    assert "/api/safety/override" in joined
    assert "/scenario/activate" in joined and "/scenario/deactivate" in joined


def test_cli_engagements_parse_with_explicit_scenario():
    engs = C.parse_engagements("team-01:power,team-02:hospital:HOSPITAL-PHI-EXFIL-01")
    assert len(engs) == 2
    assert engs[0].team_id == "team-01" and engs[0].sector == "power"
    assert engs[0].resolved_scenario_id() == "POWERPLANT-MODBUS-SABOTAGE-01"  # 기본값
    assert engs[1].scenario_id == "HOSPITAL-PHI-EXFIL-01"  # 명시값


def test_cli_engagements_parse_rejects_malformed():
    with pytest.raises(ValueError):
        C.parse_engagements("team-only-no-sector")
    with pytest.raises(ValueError):
        C.parse_engagements("")


def test_main_dry_run_returns_zero(capsys):
    rc = C.main(["--engagements", "team-01:power,team-02:water", "--dry-run"])
    assert rc == 0
    assert "dry-run" in capsys.readouterr().out
