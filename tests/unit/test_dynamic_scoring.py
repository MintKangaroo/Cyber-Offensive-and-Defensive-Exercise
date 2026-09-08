"""동적 점수(dynamic scoring) — 해결 팀 수 반비례 감소 순수함수·엔드포인트 계약 고정.

challenge_portal 의 _dynamic_points 는 최초 해결 만점→solve 증가 시 단조감소→하한 보장.
동적 스코어보드는 별도 엔드포인트라 기존 정적 스코어보드/challenges 계약을 깨지 않는다.
"""
from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def portal(tmp_path, monkeypatch):
    monkeypatch.setenv("CHALLENGE_SECRET", "unit-dyn-secret")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("DYNAMIC_SCORING", "true")
    import services.challenge_portal.main as m
    importlib.reload(m)
    return m


def test_first_solver_full_points(portal):
    base = 500
    assert portal._dynamic_points(base, 0) == base   # 아무도 못 풂 → 만점 잠재
    assert portal._dynamic_points(base, 1) == base   # 최초 해결 → 만점


def test_monotonic_decreasing_with_solves(portal):
    base = 500
    seq = [portal._dynamic_points(base, s) for s in range(1, 30)]
    assert all(seq[i] >= seq[i + 1] for i in range(len(seq) - 1))  # 단조 비증가
    assert seq[-1] < base                                          # 결국 감소


def test_floor_enforced(portal):
    base = 500
    floor = max(1, round(base * portal.DYNAMIC_MIN_RATIO))
    assert portal._dynamic_points(base, 100000) == floor          # 많이 풀려도 하한
    assert portal._dynamic_points(0, 5) == 0                       # base 0 → 0


def test_solve_count_and_dynamic_fields_in_listing(portal):
    # 두 팀이 서로 다른 문제를 solve → solve_count/dynamic_points 반영
    client = TestClient(portal.app)
    cid = next(iter(portal.CATALOG))
    portal._SOLVES["t1"] = {cid: {"points": portal.CATALOG[cid]["points_red"], "at": 1.0}}
    portal._SOLVES["t2"] = {cid: {"points": portal.CATALOG[cid]["points_red"], "at": 2.0}}
    detail = client.get(f"/portal/challenges/{cid}").json()
    assert detail["solve_count"] == 2
    # 2팀 해결 → 동적 점수는 정적 base 이하
    assert detail["dynamic_points"] <= detail["points_red"]


def test_dynamic_scoreboard_endpoint_and_static_intact(portal):
    client = TestClient(portal.app)
    cid = next(iter(portal.CATALOG))
    portal._SOLVES["t1"] = {cid: {"points": 999, "at": 1.0}}
    # 정적 스코어보드는 solve 시점 저장 점수(999) 유지 — 계약 무손상
    static = client.get("/portal/scoreboard").json()["scoreboard"]
    assert next(r for r in static if r["team_id"] == "t1")["points"] == 999
    # 동적 스코어보드는 현재 solve 수 기준 재계산(별도 엔드포인트)
    dyn = client.get("/portal/scoreboard/dynamic").json()
    assert dyn["scoring"] == "dynamic"
    row = next(r for r in dyn["scoreboard"] if r["team_id"] == "t1")
    assert row["points"] == portal._dynamic_points(portal.CATALOG[cid]["points_red"], 1)
