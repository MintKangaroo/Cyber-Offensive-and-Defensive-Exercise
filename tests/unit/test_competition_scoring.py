"""대회 세트 스코어링 정책(정적/동적) + first-blood 보너스 계약 고정.

competition_scoreboard 가 매니페스트의 scoring.mode 와 first_blood_bonus 를 기본 적용하는지
검증한다(세트별 정책·first-blood 회귀 방지).
"""
from __future__ import annotations

import importlib

import pytest


@pytest.fixture()
def portal(tmp_path, monkeypatch):
    monkeypatch.setenv("CHALLENGE_SECRET", "unit-scoring-secret")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    import services.challenge_portal.main as m
    importlib.reload(m)
    return m


def test_manifest_scoring_policy_parsed(portal):
    c = portal.COMPETITIONS["cce-infra-final-2026"]
    assert c["scoring"]["mode"] == "dynamic"
    assert c["first_blood_bonus"] == 50
    assert portal.COMPETITIONS["cce-infra-beginner"]["scoring"]["mode"] == "static"


def test_first_blood_bonus_to_earliest_solver(portal):
    c = portal.COMPETITIONS["cce-infra-final-2026"]
    cid = c["challenges"][0]
    base = portal.CATALOG[cid]["points_red"]
    # A 가 먼저, B 가 나중에 같은 문제 solve
    portal._SOLVES["A"] = {cid: {"points": base, "at": 10.0}}
    portal._SOLVES["B"] = {cid: {"points": base, "at": 20.0}}
    rows = {r["team_id"]: r for r in portal._competition_standings(c)}
    # dynamic: solve_count=2 → 두 팀 동일 base_dyn, 단 A 는 first-blood 보너스(+50)
    dyn = portal._dynamic_points(base, 2, k=c["scoring"]["k"], min_ratio=c["scoring"]["min_ratio"])
    assert rows["A"]["first_bloods"] == 1 and rows["B"]["first_bloods"] == 0
    assert rows["A"]["points"] == dyn + 50
    assert rows["B"]["points"] == dyn
    assert rows["A"]["points"] > rows["B"]["points"]


def test_static_set_uses_base_and_configured_bonus(portal):
    c = portal.COMPETITIONS["cce-infra-beginner"]  # static, bonus 0
    cid = c["challenges"][0]
    base = portal.CATALOG[cid]["points_red"]
    portal._SOLVES["A"] = {cid: {"points": base, "at": 5.0}}
    portal._SOLVES["B"] = {cid: {"points": base, "at": 6.0}}
    rows = {r["team_id"]: r for r in portal._competition_standings(c)}
    # static: base 그대로, bonus 0 → 두 팀 동점(정렬은 last_solve 로)
    assert rows["A"]["points"] == base and rows["B"]["points"] == base


def test_endpoint_exposes_scoring_and_first_blood(portal):
    r = portal.competition_scoreboard("cce-infra-final-2026")
    assert r["scoring"]["mode"] == "dynamic"
    assert r["first_blood_bonus"] == 50
    assert "scoreboard" in r
