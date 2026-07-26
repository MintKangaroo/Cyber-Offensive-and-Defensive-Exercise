"""
AAR 확장(P2-4) 순수 요약 로직 계약 고정.
이번 세션에 추가된 하위시스템(인시던트·인젝트·안티치트·ICS 프로토콜)을 AAR 리포트로 종합.
"""
from services.aar_report.integrations import (
    summarize_incidents, summarize_injects, summarize_integrity, summarize_protocol_attacks,
)


def test_summarize_incidents_counts_and_means():
    incidents = [
        {"severity": "critical", "status": "closed", "created_at": 0, "acknowledged_at": 60, "closed_at": 600,
         "sla": {"response_breached": False, "resolution_breached": False}},
        {"severity": "high", "status": "triage", "created_at": 0, "acknowledged_at": 120, "closed_at": None,
         "sla": {"response_breached": True, "resolution_breached": False}},
    ]
    s = summarize_incidents(incidents)
    assert s["total"] == 2 and s["open"] == 1 and s["breached"] == 1
    assert s["avg_mtta_sec"] == 90          # (60+120)/2
    assert s["avg_mttr_sec"] == 600          # 종결된 1건만
    assert s["by_severity"] == {"critical": 1, "high": 1}


def test_summarize_incidents_empty():
    s = summarize_incidents([])
    assert s["total"] == 0 and s["avg_mtta_sec"] is None and s["avg_mttr_sec"] is None


def test_summarize_injects_averages():
    board = [
        {"team_id": "a", "response_rate": 100, "on_time_rate": 100, "score_pct": 90},
        {"team_id": "b", "response_rate": 50, "on_time_rate": 0, "score_pct": 40},
    ]
    s = summarize_injects(board)
    assert s["teams"] == 2 and s["avg_response_rate"] == 75 and s["avg_on_time_rate"] == 50
    assert s["avg_score_pct"] == 65


def test_summarize_integrity_flags():
    flagged = [{"cid": "web-01", "teams": 2, "team_list": "a,b"}]
    s = summarize_integrity(flagged)
    assert s["flagged_count"] == 1 and s["clean"] is False and s["cases"][0]["cid"] == "web-01"


def test_summarize_integrity_clean():
    s = summarize_integrity([])
    assert s["flagged_count"] == 0 and s["clean"] is True


def test_summarize_protocol_attacks_groups_by_register():
    events = [
        {"event_type": "red_attack_started", "vuln_id": "PP-006",
         "metadata": {"protocol": "modbus", "register": "TURBINE_RPM", "values": [6000]}},
        {"event_type": "red_attack_started", "vuln_id": "PP-006",
         "metadata": {"protocol": "modbus", "register": "SAFETY_INTERLOCK", "values": [False]}},
        {"event_type": "red_attack_started", "vuln_id": "PP-001", "metadata": {"register": "X"}},  # 비프로토콜
    ]
    s = summarize_protocol_attacks(events)
    assert s["total"] == 2 and s["by_protocol"] == {"modbus": 2}
    assert set(s["by_register"]) == {"TURBINE_RPM", "SAFETY_INTERLOCK"}


def test_summarize_protocol_attacks_none():
    s = summarize_protocol_attacks([{"event_type": "x", "metadata": {}}])
    assert s["total"] == 0


def test_summarize_protocol_attacks_string_metadata():
    # replay 경로는 metadata 를 JSON 문자열로 준다(DB TEXT) — 정규화되어야 함.
    events = [{"event_type": "red_attack_started",
               "metadata": '{"protocol": "modbus", "register": "TURBINE_RPM"}'}]
    s = summarize_protocol_attacks(events)
    assert s["total"] == 1 and s["by_protocol"] == {"modbus": 1}
