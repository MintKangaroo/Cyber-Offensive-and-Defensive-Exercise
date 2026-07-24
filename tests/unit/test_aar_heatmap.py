"""
AAR ATT&CK 히트맵 유닛 테스트 (M6 버그 회귀 방지)
===================================================
핵심 회귀: mitre가 JSON 문자열('["T1059"]')로 오면 문자 단위로 순회돼
기술 ID가 '[','"','T'... 개별 문자로 쪼개지던 버그. _as_list가 이를 막아야 함.
"""
import json
from services.aar_report.attack_heatmap import _as_list, build_heatmap, uncovered_techniques


# --- _as_list 정규화 --------------------------------------------------------

def test_as_list_passthrough():
    assert _as_list(["T1059", "T1078"]) == ["T1059", "T1078"]


def test_as_list_json_string():
    """M6 회귀: 문자열은 파싱해야지, 문자 단위로 쪼개면 안 됨."""
    assert _as_list(json.dumps(["T1059"])) == ["T1059"]


def test_as_list_plain_string_not_char_split():
    # JSON이 아닌 단일 문자열은 통째로 한 원소
    assert _as_list("T1059") == ["T1059"]
    assert "T" not in _as_list("T1059")[0:0]  # 문자 쪼개짐 없음
    assert _as_list("T1059") != ["T", "1", "0", "5", "9"]


def test_as_list_none():
    assert _as_list(None) == []


# --- build_heatmap ----------------------------------------------------------

def test_heatmap_occurred_and_detected():
    events = [{"event_type": "red_attack_started", "metadata": {"mitre": ["T1059"]}}]
    alerts = [{"rule_id": "SIEM-1", "mitre": ["T1059"]}]
    hm = build_heatmap(events, alerts)
    assert hm["T1059"]["occurred"] is True
    assert hm["T1059"]["detected"] is True
    assert "SIEM-1" in hm["T1059"]["rule_ids"]


def test_heatmap_json_string_mitre_no_char_split():
    """M6 회귀: 문자열 mitre도 정확한 기술 키로 집계(한 글자 키 금지)."""
    events = [{"event_type": "red_attack_started", "metadata": {"mitre": json.dumps(["T1110"])}}]
    hm = build_heatmap(events, [])
    assert "T1110" in hm
    assert "[" not in hm and '"' not in hm   # 쪼개진 문자 키가 없어야 함


def test_uncovered_techniques():
    events = [
        {"event_type": "red_attack_started", "metadata": {"mitre": ["T1059"]}},
        {"event_type": "red_attack_started", "metadata": {"mitre": ["T1078"]}},
    ]
    alerts = [{"rule_id": "R", "mitre": ["T1059"]}]   # T1078은 미탐지
    hm = build_heatmap(events, alerts)
    assert uncovered_techniques(hm) == ["T1078"]
