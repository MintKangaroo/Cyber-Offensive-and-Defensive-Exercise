"""
Incident Case Management(P1) 순수 로직 계약 고정.
- 라이프사이클 상태전이(허용/거부)
- 심각도별 SLA + 위반 판정
- MTTA/MTTR 지표 계산(AAR 연동)
"""
import pytest

from services.incident.model import (
    STATUSES, can_transition, sla_for, sla_breaches, compute_metrics,
)


def test_lifecycle_order_defined():
    assert STATUSES[0] == "new" and STATUSES[-1] == "closed"


@pytest.mark.parametrize("frm,to,ok", [
    ("new", "triage", True),
    ("new", "closed", True),          # 오탐 즉시 종결 허용
    ("new", "recovered", False),      # 단계 건너뛰기 금지
    ("triage", "contained", True),
    ("contained", "eradicated", True),
    ("eradicated", "recovered", True),
    ("recovered", "closed", True),
    ("closed", "triage", False),      # 종결 후 재개 금지
    ("contained", "new", False),      # 역행 금지
])
def test_transition_rules(frm, to, ok):
    assert can_transition(frm, to) is ok


def test_sla_scales_with_severity():
    crit = sla_for("critical"); low = sla_for("low")
    assert crit["response_min"] < low["response_min"]
    assert crit["resolution_min"] < low["resolution_min"]


def test_unknown_severity_defaults_medium():
    assert sla_for("bogus") == sla_for("medium")


def test_sla_response_breach_when_ack_late():
    # critical response SLA=15분. 20분 뒤 첫 대응 → 위반.
    inc = {"severity": "critical", "created_at": 0, "acknowledged_at": 20 * 60,
           "closed_at": None}
    b = sla_breaches(inc, now=20 * 60)
    assert b["response_breached"] is True and b["resolution_breached"] is False


def test_sla_no_breach_when_prompt():
    inc = {"severity": "critical", "created_at": 0, "acknowledged_at": 5 * 60,
           "closed_at": 30 * 60}
    b = sla_breaches(inc, now=30 * 60)
    assert b["response_breached"] is False and b["resolution_breached"] is False


def test_sla_resolution_breach_open_and_overdue():
    # 아직 안 닫혔고(now) resolution SLA 초과 → 위반.
    inc = {"severity": "high", "created_at": 0, "acknowledged_at": 60,
           "closed_at": None}
    b = sla_breaches(inc, now=10 * 60 * 60)   # 10시간 (high resolution=480분=8h)
    assert b["resolution_breached"] is True


def test_metrics_mtta_mttr():
    inc = {"created_at": 100, "acknowledged_at": 400, "closed_at": 2100}
    m = compute_metrics(inc)
    assert m["mtta_sec"] == 300 and m["mttr_sec"] == 2000


def test_metrics_open_incident_has_no_mttr():
    inc = {"created_at": 100, "acknowledged_at": 400, "closed_at": None}
    m = compute_metrics(inc)
    assert m["mtta_sec"] == 300 and m["mttr_sec"] is None
