"""
통합 타임라인(shared/timeline.py) 순수 병합 로직 계약 고정.
서로 다른 소스(이벤트·SIEM 알림·인시던트·인젝트)를 시간순 단일 뷰로 병합한다.
합성 데이터만 사용(도커 불필요, 결정론 검증).
"""
from shared.timeline import build_timeline


def test_merge_ordering_interleaves_by_ts():
    # 서로 다른 소스가 시각 순서대로 뒤섞여 정렬돼야 한다.
    sources = {
        "events": [{"event_id": "e1", "event_type": "red_attack_started",
                    "timestamp": 100.0, "actor": "red", "target_asset": "power_plant"}],
        "alerts": [{"id": "a1", "title": "Modbus write", "severity": 3, "timestamp": 150.0}],
        "incidents": [{"id": "i1", "title": "PP down", "severity": "high", "created_at": 300.0}],
    }
    tl = build_timeline(sources)
    assert [x["ref"] for x in tl] == ["e1", "a1", "i1"]
    assert [x["ts"] for x in tl] == [100.0, 150.0, 300.0]


def test_each_source_kind_normalized():
    sources = {
        "events": [{"event_id": "e1", "event_type": "asset_compromised",
                    "timestamp": 10.0, "actor": "red", "target_asset": "dmz"}],
        "alerts": [{"id": "a1", "title": "brute force", "severity": 2, "timestamp": 20.0,
                    "matched_event": {"asset": "ground_station"}}],
        "incidents": [{"id": "i1", "title": "leak", "severity": "critical",
                       "created_at": 30.0, "host": "web01"}],
        "injects": [{"team_id": "blue1", "response_rate": 80}],
    }
    tl = build_timeline(sources)
    by_ref = {x["ref"]: x for x in tl}

    ev = by_ref["e1"]
    assert ev["kind"] == "asset_compromised" and ev["source"] == "event_collector"
    assert ev["actor"] == "red" and ev["asset"] == "dmz"
    assert ev["title"] == "asset_compromised — dmz"

    al = by_ref["a1"]
    assert al["kind"] == "alert" and al["source"] == "siem"
    assert al["severity"] == 2 and al["asset"] == "ground_station"

    inc = by_ref["i1"]
    assert inc["kind"] == "incident" and inc["source"] == "incident"
    assert inc["actor"] == "blue" and inc["asset"] == "web01" and inc["severity"] == "critical"

    inj = by_ref["blue1"]
    assert inj["kind"] == "inject" and inj["source"] == "injects"
    assert inj["actor"] == "blue1" and inj["ts"] is None  # 스코어보드엔 시각 없음


def test_injects_without_ts_sorted_last():
    sources = {
        "events": [{"event_id": "e1", "event_type": "flag_exfiltrated", "timestamp": 500.0}],
        "injects": [{"team_id": "t1", "response_rate": 100},
                    {"team_id": "t2", "response_rate": 50}],
    }
    tl = build_timeline(sources)
    # 시각 있는 엔트리가 먼저, ts=None 인젝트 요약은 맨 뒤(결정론적 tie-break).
    assert tl[0]["ref"] == "e1"
    assert [x["ref"] for x in tl[1:]] == ["t1", "t2"]


def test_empty_sources():
    assert build_timeline({}) == []
    assert build_timeline({"events": [], "alerts": [], "incidents": [], "injects": []}) == []


def test_deterministic_tie_break_on_equal_ts():
    # 동일 ts → (source, kind, ref) 기준 안정·결정론 정렬. 입력 순서와 무관하게 동일 결과.
    a = {
        "events": [{"event_id": "z", "event_type": "score_updated", "timestamp": 42.0}],
        "alerts": [{"id": "b", "title": "x", "severity": 1, "timestamp": 42.0}],
        "incidents": [{"id": "m", "title": "y", "severity": "low", "created_at": 42.0}],
    }
    b = {
        "incidents": [{"id": "m", "title": "y", "severity": "low", "created_at": 42.0}],
        "alerts": [{"id": "b", "title": "x", "severity": 1, "timestamp": 42.0}],
        "events": [{"event_id": "z", "event_type": "score_updated", "timestamp": 42.0}],
    }
    r1 = [x["ref"] for x in build_timeline(a)]
    r2 = [x["ref"] for x in build_timeline(b)]
    assert r1 == r2
    # source 알파벳 순(event_collector < incident < siem)으로 tie-break.
    assert r1 == ["z", "m", "b"]


def test_iso_string_timestamp_normalized():
    # SIEM/트윈 경로가 ISO 문자열을 줄 수 있음 — epoch 로 정규화되어 정렬돼야.
    sources = {
        "alerts": [{"id": "a1", "title": "iso", "severity": 0,
                    "timestamp": "2026-01-01T00:00:00+00:00"}],
        "events": [{"event_id": "e1", "event_type": "scenario_started", "timestamp": 0.0}],
    }
    tl = build_timeline(sources)
    assert tl[0]["ref"] == "e1"       # epoch 0 < 2026
    assert isinstance(tl[1]["ts"], float) and tl[1]["ts"] > 0
