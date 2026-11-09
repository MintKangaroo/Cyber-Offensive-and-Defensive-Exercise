"""탐지 dwell-time 보너스 라이브 회귀 — 빠른 탐지일수록 높은 blue_detection_success 점수.

#147 라이브는 detection_success 의 base 20 만 실증했다(그때 dwell=0). dwell 보너스 경로는 두 서비스에
걸쳐 있고, 지금껏 어떤 유닛도 그 두 경계를 고정하지 않았다:

  (1) event_collector._build_forward_payload — 탐지 이벤트의 matched_event_id 로 원 공격 이벤트의
      timestamp 를 조회(_lookup_matched_timestamp)해 metadata['_matched_timestamp'] 로 enrichment
      한다. 대응 공격을 못 찾으면 _unmatched 플래그만 세운다(04번 1절 오탐/치팅 신호).
  (2) scoring_engine._dwell_bonus + score_ingest — 탐지 timestamp 와 _matched_timestamp 의 차(dwell)
      로 보너스 = max(0, 20 - floor(dwell/30)) 를 base 20 에 더한다.

enrichment(1) 가 끊기거나 decay 공식(2) 가 바뀌어도, HTTP 응답/발행만 보는 기존 테스트는 전부 통과하고
라이브 스코어보드의 탐지 점수만 조용히 틀어진다(항상 20, 혹은 항상 40). 이 파일이 그 두 경계를 고정한다.

2026-11-09 라이브 E2E 로 실증(collector:8010 + scoring:8020, 소스 무변경):
  R1 red_attack_started(ts=10000) → D1 blue_detection_success(matched=R1, ts=10005, dwell 5s)   → 40
  R2 red_attack_started(ts=20000) → D2 blue_detection_success(matched=R2, ts=20100, dwell 100s)  → 37 (decay)
                                     D3 blue_detection_success(matched=GHOST, unmatched)          → 20 (base)
  /scores → {default:{red:40, blue:97}},  /scores/history 어워드 points = 40 / 37 / 20.
  blue=97 은 per-detection dwell(40+37+20)로만 설명된다(평탄 20이면 60, 항상 +20이면 다른 값).
"""
import math
import os

os.environ.setdefault("RBAC_ALLOW_INSECURE_DEV", "true")

import pytest

from services.scoring_engine import main as sc
from services.event_collector import main as ec
from shared.event_schema import Event


# ---------------------------------------------------------------------------
# (2a) _dwell_bonus — 순수 decay 공식: 30초마다 1점씩, [0, 20] 로 클램프
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "dwell_sec,expected",
    [
        (0, 20),      # 즉시 탐지 → 만점 보너스
        (29, 20),     # 첫 30초 구간 전체가 +20 (floor(29/30)=0)
        (30, 19),     # 경계: 30초부터 1점 감소
        (59, 19),     # 다음 경계 직전
        (60, 18),     # 2구간
        (100, 17),    # 라이브 D2 와 동일(floor(100/30)=3 → 20-3)
        (570, 1),     # 마지막 양수 구간(floor(570/30)=19 → 20-19)
        (600, 0),     # 10분이면 보너스 소멸(floor=20 → 0)
        (5000, 0),    # 그 이후는 음수가 아니라 0 으로 클램프
    ],
)
def test_dwell_bonus_decays_by_30s_and_clamps(dwell_sec, expected):
    md = {"_matched_timestamp": 1000.0, "_detection_timestamp": 1000.0 + dwell_sec}
    assert sc._dwell_bonus(md) == expected
    # 공식 자체도 재확인(회귀 시 어느 쪽이 틀어졌는지 구분)
    assert expected == max(0, 20 - math.floor(dwell_sec / 30))


def test_dwell_bonus_negative_dwell_clamps_to_full():
    # 탐지 timestamp 가 공격보다 이르면(클럭 스큐) dwell 은 음수가 아니라 0 → 만점.
    md = {"_matched_timestamp": 2000.0, "_detection_timestamp": 1900.0}
    assert sc._dwell_bonus(md) == 20


@pytest.mark.parametrize("md", [
    {},                                          # enrichment 전혀 없음
    {"_detection_timestamp": 1005.0},            # 매칭 공격 timestamp 없음(_unmatched 경로)
    {"_matched_timestamp": 1000.0},              # 탐지 timestamp 없음
])
def test_dwell_bonus_zero_without_both_timestamps(md):
    # 둘 중 하나라도 없으면 보너스 0 → base 20 만. (enrichment 가 끊기면 '빠른 탐지'가 보상 안 됨)
    assert sc._dwell_bonus(md) == 0


# ---------------------------------------------------------------------------
# (2b) score_ingest — blue_detection_success 는 base 20 + dwell 보너스로 적립된다
# ---------------------------------------------------------------------------
@pytest.fixture
def scoring_db(tmp_path, monkeypatch):
    monkeypatch.setattr(sc, "DB_PATH", tmp_path / "scores.db")
    sc.init_db()
    return sc.DB_PATH


def _detection(event_id, vuln, det_ts, matched_ts):
    md = {}
    if matched_ts is not None:
        md["_matched_timestamp"] = matched_ts
    return sc.IncomingEvent(
        event_id=event_id, event_type="blue_detection_success", timestamp=det_ts,
        actor="blue", target_asset="power_plant", vuln_id=vuln, matched_event_id="X",
        metadata=md,
    )


def test_score_ingest_fast_detection_awards_base_plus_full_bonus(scoring_db):
    # 라이브 D1: dwell 5s → 20 + 20 = 40
    res = sc.score_ingest(_detection("D1", "PP-001", det_ts=10005.0, matched_ts=10000.0))
    assert res == {"awarded": True, "category": "detection_success", "points": 40}


def test_score_ingest_slow_detection_awards_decayed_bonus(scoring_db):
    # 라이브 D2: dwell 100s → 20 + 17 = 37
    res = sc.score_ingest(_detection("D2", "PP-002", det_ts=20100.0, matched_ts=20000.0))
    assert res == {"awarded": True, "category": "detection_success", "points": 37}


def test_score_ingest_unmatched_detection_awards_base_only(scoring_db):
    # 라이브 D3: 매칭 공격 없음(enrichment 안 됨) → base 20 만
    res = sc.score_ingest(_detection("D3", "PP-003", det_ts=30000.0, matched_ts=None))
    assert res == {"awarded": True, "category": "detection_success", "points": 20}


def test_score_ingest_dwell_accumulates_on_blue_team_score(scoring_db):
    # 세 탐지가 팀 blue 점수로 누적(40+37+20=97) — 라이브 /scores blue=97 과 동일한 합.
    sc.score_ingest(_detection("D1", "PP-001", 10005.0, 10000.0))
    sc.score_ingest(_detection("D2", "PP-002", 20100.0, 20000.0))
    sc.score_ingest(_detection("D3", "PP-003", 30000.0, None))
    conn = sc.get_db()
    row = conn.execute(
        "SELECT score FROM team_scores WHERE team_id='default' AND scenario_id='default' AND actor='blue'"
    ).fetchone()
    conn.close()
    assert row["score"] == 97


# ---------------------------------------------------------------------------
# (1) _build_forward_payload — collector 가 dwell 계산에 필요한 원 공격 timestamp 를 붙여준다
# ---------------------------------------------------------------------------
def _det_event(matched_event_id):
    return Event(
        event_id="D1", event_type="blue_detection_success", actor="blue",
        target_asset="power_plant", vuln_id="PP-001", matched_event_id=matched_event_id,
        timestamp=10005.0,
    )


def test_build_forward_payload_enriches_matched_timestamp_when_attack_found(monkeypatch):
    # 원 공격 이벤트를 DB 에서 찾으면 그 timestamp 를 _matched_timestamp 로 실어 보낸다(dwell 계산 가능).
    monkeypatch.setattr(ec, "_lookup_matched_timestamp", lambda eid: 10000.0 if eid == "R1" else None)
    payload = ec._build_forward_payload(_det_event("R1"))
    assert payload["metadata"]["_matched_timestamp"] == 10000.0
    assert "_unmatched" not in payload["metadata"]


def test_build_forward_payload_flags_unmatched_when_attack_missing(monkeypatch):
    # 대응 공격을 못 찾으면 _matched_timestamp 를 붙이지 않고 _unmatched 신호만(→ scoring dwell 0).
    monkeypatch.setattr(ec, "_lookup_matched_timestamp", lambda eid: None)
    payload = ec._build_forward_payload(_det_event("GHOST"))
    assert payload["metadata"]["_unmatched"] is True
    assert "_matched_timestamp" not in payload["metadata"]


def test_build_forward_payload_no_correlation_without_matched_event_id(monkeypatch):
    # matched_event_id 자체가 없으면(순수 공격/상관 없는 이벤트) 조회도, 두 플래그도 없다.
    called = []
    monkeypatch.setattr(ec, "_lookup_matched_timestamp", lambda eid: called.append(eid))
    payload = ec._build_forward_payload(_det_event(None))
    assert called == []
    md = payload.get("metadata", {})
    assert "_matched_timestamp" not in md
    assert "_unmatched" not in md
