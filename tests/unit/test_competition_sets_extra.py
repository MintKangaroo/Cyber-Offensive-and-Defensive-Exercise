"""추가 대회 세트(예선/입문/상급) — 매니페스트 로딩·성격(난이도 편향) 회귀 고정.

challenge_portal 이 competitions/*.yaml 를 자동 로드하므로, 새 세트가 포털 CATALOG 기준으로
정상 로드되고 각 세트의 난이도 성격(예선<본선<상급 방향의 easy/hard 편향)이 유지되는지 검증한다.
"""
from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient

QUALS = "cce-infra-quals-2026"
BEGINNER = "cce-infra-beginner"
HARDCORE = "cce-infra-hardcore"
FINAL = "cce-infra-final-2026"
SYSHACK = "cce-infra-syshack-2026"


@pytest.fixture()
def portal(tmp_path, monkeypatch):
    monkeypatch.setenv("CHALLENGE_SECRET", "unit-sets-secret")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    import services.challenge_portal.main as m
    importlib.reload(m)
    return m


def _easy_ratio(c: dict) -> float:
    d = c["by_difficulty"]
    return d.get("easy", 0) / max(c["count"], 1)


def test_new_sets_loaded_and_all_ids_exist(portal):
    comps = portal.COMPETITIONS
    for sid, lo, hi in [(QUALS, 20, 30), (BEGINNER, 10, 15), (HARDCORE, 12, 24)]:
        assert sid in comps, f"{sid} 미로드"
        c = comps[sid]
        assert c["count"] > 0
        # 로더는 CATALOG 에 없는 ID 를 필터한다 → 필터 후에도 예상 범위(모든 ID 가 red 로 존재)
        assert lo <= c["count"] <= hi, f"{sid} count={c['count']}"
        # detection(blue)은 red 세트에 포함되지 않아야 함
        assert "detection" not in c["by_category"]


def test_difficulty_profiles(portal):
    comps = portal.COMPETITIONS
    beginner, quals, final, hard = (comps[BEGINNER], comps[QUALS],
                                    comps[FINAL], comps[HARDCORE])
    # 입문 ≥ 예선 (easy 비중), 예선 ≥ 본선 (easy 비중)
    assert _easy_ratio(beginner) >= _easy_ratio(quals) >= _easy_ratio(final)
    # 상급은 hard+insane 이 과반
    hd = hard["by_difficulty"]
    assert (hd.get("hard", 0) + hd.get("insane", 0)) > hard["count"] / 2
    # 예선은 hard 가 없고 insane 은 최대 1
    qd = quals["by_difficulty"]
    assert qd.get("hard", 0) == 0 and qd.get("insane", 0) <= 1


def test_listing_endpoint_includes_new_sets(portal):
    client = TestClient(portal.app)
    ids = {x["id"] for x in client.get("/portal/competitions").json()["competitions"]}
    assert {QUALS, BEGINNER, HARDCORE, SYSHACK}.issubset(ids)
    detail = client.get(f"/portal/competitions/{HARDCORE}").json()
    assert detail["count"] == len(detail["challenges"]) > 0


def test_syshack_set_is_crypto_pwn_only(portal):
    """시스템 해킹 집중전: 암호(crypto)·포너블(pwn) 특화 세트 — 신규 유형 실전 투입 회귀 고정."""
    comps = portal.COMPETITIONS
    assert SYSHACK in comps, f"{SYSHACK} 미로드"
    c = comps[SYSHACK]
    # crypto·pwn 만으로 구성
    assert set(c["by_category"]) == {"crypto", "pwn"}, c["by_category"]
    # 이번 확장 신규 유형이 실제 편성됐는지(대표 ID 존재)
    for cid in ("CRY-003", "CRY-004", "CRY-005", "PWN-005", "PWN-006", "PWN-007"):
        assert cid in c["challenges"], f"{cid} 미편성"
    # 동적 점수 + first-blood 정책
    assert c["scoring"]["mode"] == "dynamic" and c["first_blood_bonus"] == 50
    # detection(blue)은 red 세트에 미포함
    assert "detection" not in c["by_category"]
