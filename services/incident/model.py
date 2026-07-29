"""
Incident 순수 로직(P1 Incident Case Management)
================================================
상태머신·SLA·지표를 상태 없는 순수함수로 분리(테스트 용이). 서비스(main.py)는 이 규칙을
sqlite 위에 적용한다.

라이프사이클: new → triage → contained → eradicated → recovered → closed
(new/triage 에서는 오탐으로 즉시 closed 가능. 역행·건너뛰기·재개는 금지.)
"""
from __future__ import annotations

# 표준 IR 라이프사이클(NIST SP 800-61 억제/근절/복구 반영)
STATUSES = ["new", "triage", "contained", "eradicated", "recovered", "closed"]

_TRANSITIONS: dict[str, set[str]] = {
    "new": {"triage", "closed"},
    "triage": {"contained", "closed"},
    "contained": {"eradicated"},
    "eradicated": {"recovered"},
    "recovered": {"closed"},
    "closed": set(),
}

# 심각도별 SLA(분): 응답(첫 대응)·해결(종결)
_SLA = {
    "critical": {"response_min": 15, "resolution_min": 240},
    "high":     {"response_min": 30, "resolution_min": 480},
    "medium":   {"response_min": 60, "resolution_min": 1440},
    "low":      {"response_min": 240, "resolution_min": 4320},
}


def can_transition(frm: str, to: str) -> bool:
    return to in _TRANSITIONS.get(frm, set())


def sla_for(severity: str) -> dict:
    return _SLA.get((severity or "").lower(), _SLA["medium"])


def sla_breaches(inc: dict, now: float) -> dict:
    """응답/해결 SLA 위반 여부.
    - 응답: acknowledged_at 이 없으면 now 기준, 있으면 그 시각 기준으로 판정.
    - 해결: closed_at 이 없으면(진행 중) now 기준, 있으면 종결 시각 기준.
    """
    sla = sla_for(inc.get("severity", "medium"))
    created = inc.get("created_at") or 0
    ack = inc.get("acknowledged_at")
    resp_elapsed = ((ack if ack is not None else now) - created)
    closed = inc.get("closed_at")
    res_elapsed = ((closed if closed is not None else now) - created)
    return {
        "response_breached": resp_elapsed > sla["response_min"] * 60,
        "resolution_breached": res_elapsed > sla["resolution_min"] * 60,
        "response_sla_min": sla["response_min"],
        "resolution_sla_min": sla["resolution_min"],
    }


def find_resolvable(incidents: list, recovered_assets: set) -> list:
    """복구된 자산(asset_recovered)과 상관되는 '미해결·미주석' 인시던트 id 목록.
    자동 close 하지 않고 타임라인 주석 + 해결 힌트만 → Blue 가 판단(훈련 주체성 유지)."""
    out = []
    for inc in incidents:
        if inc.get("status") == "closed":
            continue
        host = inc.get("host")
        if not host or host not in recovered_assets:
            continue
        tl = inc.get("timeline") or []
        if any(t.get("action") == "recovery_detected" for t in tl):
            continue   # 이미 주석됨(중복 방지)
        out.append(inc["id"])
    return out


def compute_metrics(inc: dict) -> dict:
    """AAR 연동 지표. MTTA(응답까지)·MTTR(해결까지). 진행 중이면 MTTR=None."""
    created = inc.get("created_at") or 0
    ack = inc.get("acknowledged_at")
    closed = inc.get("closed_at")
    return {
        "mtta_sec": (ack - created) if ack is not None else None,
        "mttr_sec": (closed - created) if closed is not None else None,
    }
