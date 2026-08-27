"""
AAR 지표 계산 유닛 테스트 (M6 + P1-1 버그 회귀 방지)
======================================================
검증 대상 버그:
 - metadata가 JSON 문자열로 와도 MTTR이 계산돼야 함(P1-1: metrics.py:52 크래시)
 - MTTD/탐지율이 event_id **또는** trace_id 어느 쪽으로 상관해도 잡혀야 함
   (M6: SIEM은 matched_event_id에 trace_id를 넣어 event_id 조인만 하면 전부 0/None)
"""
import json

import pytest

from services.aar_report.metrics import (
    _metadata, compute_mttr, compute_mttd, compute_detection_rate,
    compute_false_positive_rate,
)


# --- _metadata 정규화 -------------------------------------------------------

def test_metadata_accepts_dict():
    assert _metadata({"metadata": {"dwell_sec": 12}}) == {"dwell_sec": 12}


def test_metadata_parses_json_string():
    """sqlite 역직렬화 전 상태(JSON 문자열)를 dict로 흡수."""
    assert _metadata({"metadata": json.dumps({"dwell_sec": 5})}) == {"dwell_sec": 5}


def test_metadata_bad_string_returns_empty():
    assert _metadata({"metadata": "not-json"}) == {}


def test_metadata_missing_returns_empty():
    assert _metadata({}) == {}


# --- MTTR (dwell_sec 평균) ---------------------------------------------------

def test_mttr_none_when_no_recovery():
    events = [{"event_type": "red_objective_success", "event_id": "a", "timestamp": 1}]
    assert compute_mttr(events) is None


def test_mttr_from_dict_metadata():
    events = [
        {"event_type": "asset_recovered", "metadata": {"dwell_sec": 10.0}},
        {"event_type": "asset_recovered", "metadata": {"dwell_sec": 20.0}},
    ]
    assert compute_mttr(events) == 15.0


def test_mttr_from_json_string_metadata():
    """P1-1 회귀: metadata가 문자열이어도 크래시 없이 계산."""
    events = [{"event_type": "asset_recovered", "metadata": json.dumps({"dwell_sec": 30.0})}]
    assert compute_mttr(events) == 30.0


# --- MTTD 상관 (event_id / trace_id) ----------------------------------------

def test_mttd_correlates_by_event_id():
    events = [
        {"event_id": "atk1", "event_type": "red_attack_started", "timestamp": 100.0},
        {"event_id": "det1", "event_type": "blue_detection_success",
         "matched_event_id": "atk1", "timestamp": 105.0},
    ]
    assert compute_mttd(events) == 5.0


def test_mttd_correlates_by_trace_id():
    """M6 회귀: SIEM 탐지는 matched_event_id에 trace_id를 넣는다."""
    events = [
        {"event_id": "atk1", "event_type": "red_attack_started",
         "trace_id": "sess-9", "timestamp": 100.0},
        {"event_id": "det1", "event_type": "blue_detection_success",
         "matched_event_id": "sess-9", "timestamp": 108.0},
    ]
    assert compute_mttd(events) == 8.0


# --- 탐지율 (event_id or trace_id) ------------------------------------------

def test_detection_rate_mixed_keys():
    events = [
        {"event_id": "a1", "event_type": "red_attack_started", "trace_id": "t1"},
        {"event_id": "a2", "event_type": "red_objective_success", "trace_id": "t2"},
        {"event_type": "blue_detection_success", "matched_event_id": "a1"},   # event_id로
        {"event_type": "blue_detection_success", "matched_event_id": "t2"},   # trace_id로
    ]
    # 2개 공격 모두 탐지됨 -> 1.0
    assert compute_detection_rate(events) == 1.0


def test_detection_rate_none_when_no_attacks():
    assert compute_detection_rate([{"event_type": "asset_recovered"}]) is None


def test_detection_rate_partial():
    events = [
        {"event_id": "a1", "event_type": "red_attack_started"},
        {"event_id": "a2", "event_type": "red_attack_started"},
        {"event_type": "blue_detection_success", "matched_event_id": "a1"},
    ]
    assert compute_detection_rate(events) == 0.5


# --- 오탐률: 배경 트래픽 ground truth (감사 G-11) -----------------------------

def test_fp_rate_legacy_noise_event_id_path():
    """기존 경로: source_event_id가 노이즈 이벤트 집합에 있으면 오탐."""
    alerts = [{"source_event_id": "n1"}, {"source_event_id": "real"}]
    assert compute_false_positive_rate(alerts, {"n1"}) == 0.5


def test_fp_rate_background_via_matched_event_raw():
    """감사 G-11: 실 배경 트래픽 알림은 matched_event.raw.is_background로 오탐 판정."""
    alerts = [
        {"matched_event": {"raw": {"is_background": True}}},   # 배경 = 오탐
        {"matched_event": {"raw": {"is_background": False}}},  # 실 공격
        {"matched_event": {"tags": ["twin_access_log", "background_traffic"]}},  # 태그로도 인정
    ]
    assert compute_false_positive_rate(alerts, set()) == pytest.approx(2 / 3)


def test_fp_rate_background_and_legacy_union():
    alerts = [
        {"source_event_id": "n1"},                              # 레거시 노이즈
        {"matched_event": {"raw": {"is_background": True}}},    # 배경
        {"matched_event": {"raw": {"is_background": False}}},   # 실 공격
    ]
    assert compute_false_positive_rate(alerts, {"n1"}) == pytest.approx(2 / 3)


def test_fp_rate_none_when_no_alerts():
    assert compute_false_positive_rate([], {"n1"}) is None
