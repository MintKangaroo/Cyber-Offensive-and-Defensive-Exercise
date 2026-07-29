"""
인시던트 이벤트 상관(자동 강화) 계약 고정.
복구된 자산 → 관련 미해결 인시던트에 해결 힌트 주석(자동 close 안 함, 중복 방지).
"""
from services.incident.model import find_resolvable


def _inc(iid, status, host, tl=None):
    return {"id": iid, "status": status, "host": host, "timeline": tl or []}


def test_matches_open_incident_on_recovered_host():
    incs = [_inc("INC-1", "triage", "railway_signaling")]
    assert find_resolvable(incs, {"railway_signaling"}) == ["INC-1"]


def test_ignores_closed_incident():
    incs = [_inc("INC-1", "closed", "railway_signaling")]
    assert find_resolvable(incs, {"railway_signaling"}) == []


def test_ignores_non_recovered_host():
    incs = [_inc("INC-1", "triage", "power_plant")]
    assert find_resolvable(incs, {"railway_signaling"}) == []


def test_dedup_already_annotated():
    incs = [_inc("INC-1", "triage", "railway_signaling",
                 tl=[{"action": "recovery_detected"}])]
    assert find_resolvable(incs, {"railway_signaling"}) == []


def test_incident_without_host_skipped():
    incs = [_inc("INC-1", "new", "")]
    assert find_resolvable(incs, {"railway_signaling"}) == []


def test_multiple_incidents_same_host():
    incs = [_inc("INC-1", "new", "airport_ot"), _inc("INC-2", "contained", "airport_ot")]
    assert set(find_resolvable(incs, {"airport_ot"})) == {"INC-1", "INC-2"}
