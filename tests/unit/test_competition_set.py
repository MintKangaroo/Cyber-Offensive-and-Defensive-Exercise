"""대회 세트(competition set) — 매니페스트 로딩·밸런스·스코프 스코어보드 계약 고정.

challenge_portal 이 competitions/*.yaml 을 로드해 세트 단위 목록과, 세트에 포함된 문제 solve 만
집계하는 스코어보드를 제공하는지 검증한다(난이도·카테고리 밸런싱 튜닝의 회귀 방지).
"""
from __future__ import annotations

import importlib
import os

import pytest
from fastapi.testclient import TestClient

SET_ID = "cce-infra-final-2026"


@pytest.fixture()
def portal(tmp_path, monkeypatch):
    monkeypatch.setenv("CHALLENGE_SECRET", "unit-portal-secret")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    import services.challenge_portal.main as m
    importlib.reload(m)
    return m


def test_manifest_loaded_and_balanced(portal):
    comps = portal.COMPETITIONS
    assert SET_ID in comps
    c = comps[SET_ID]
    # red 플래그 세트: 24개(detection blue 트랙은 별도, 포털 CATALOG 미포함)
    assert c["count"] == 24
    # 카테고리 균형: red 8개 분야 모두 포함
    assert set(c["by_category"]) == {
        "web", "pwn", "crypto", "reversing", "forensics", "network", "ics", "ai"
    }
    # 난이도 곡선: easy→insane 모두 존재
    d = c["by_difficulty"]
    assert d["easy"] > 0 and d["medium"] > 0 and d["hard"] > 0 and d["insane"] > 0


def test_list_and_detail_endpoints(portal):
    client = TestClient(portal.app)
    lst = client.get("/portal/competitions").json()["competitions"]
    assert any(x["id"] == SET_ID for x in lst)
    detail = client.get(f"/portal/competitions/{SET_ID}").json()
    assert detail["count"] == 24
    assert len(detail["challenges"]) == 24
    # 공개 필드만(내부 경로 dir 없음)
    assert all("dir" not in ch for ch in detail["challenges"])
    assert client.get("/portal/competitions/does-not-exist").status_code == 404


def test_scoped_scoreboard_only_counts_set_members(portal):
    # 세트에 든 문제 1개 + 세트 밖 문제 1개를 solve 로 주입
    inset = portal.COMPETITIONS[SET_ID]["challenges"][0]
    outset = next(cid for cid in portal.CATALOG
                  if cid not in portal.COMPETITIONS[SET_ID]["challenges"])
    portal._SOLVES["teamX"] = {
        inset: {"points": 100, "at": 1.0},
        outset: {"points": 999, "at": 2.0},
    }
    sb = portal.competition_scoreboard(SET_ID)["scoreboard"]
    row = next(r for r in sb if r["team_id"] == "teamX")
    assert row["solved"] == 1           # 세트 안 문제만 집계
    assert row["points"] == 100         # 세트 밖 999 는 제외
