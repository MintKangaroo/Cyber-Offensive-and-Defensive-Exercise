"""
AAR 확장 통합(P2-4) — 순수 요약 로직
======================================
이번 세션에 추가된 하위시스템을 AAR 리포트로 종합한다. main.py 가 각 서비스에서 데이터를
가져와 이 순수함수들로 요약한다(상태 없음 → 테스트 용이).

- summarize_incidents  : 인시던트 SLA 준수·MTTA/MTTR(P1 Incident)
- summarize_injects    : 위기 커뮤니케이션 대응률·정시율·점수(P1-4 Injects)
- summarize_integrity  : 플래그 공유(담합) 무결성(P1-5 Anti-cheat)
- summarize_protocol_attacks : 실제 프로토콜(ICS Modbus 등) 공격(P1-1)
"""
from __future__ import annotations

import json


def _as_dict(md) -> dict:
    """metadata 는 replay 경로에서 JSON 문자열로 올 수 있다(DB TEXT). dict 로 정규화."""
    if isinstance(md, dict):
        return md
    if isinstance(md, str):
        try:
            v = json.loads(md)
            return v if isinstance(v, dict) else {}
        except (ValueError, TypeError):
            return {}
    return {}


def _mean(xs: list[float]):
    xs = [x for x in xs if x is not None]
    return round(sum(xs) / len(xs), 1) if xs else None


def summarize_incidents(incidents: list[dict]) -> dict:
    total = len(incidents)
    open_ = sum(1 for i in incidents if i.get("status") != "closed")
    breached = sum(1 for i in incidents
                   if (i.get("sla") or {}).get("response_breached") or (i.get("sla") or {}).get("resolution_breached"))
    mttas, mttrs = [], []
    by_sev: dict[str, int] = {}
    for i in incidents:
        by_sev[i.get("severity", "?")] = by_sev.get(i.get("severity", "?"), 0) + 1
        c = i.get("created_at")
        if c is not None and i.get("acknowledged_at") is not None:
            mttas.append(i["acknowledged_at"] - c)
        if c is not None and i.get("closed_at") is not None:
            mttrs.append(i["closed_at"] - c)
    return {
        "total": total, "open": open_, "breached": breached,
        "avg_mtta_sec": _mean(mttas), "avg_mttr_sec": _mean(mttrs),
        "by_severity": by_sev,
    }


def summarize_injects(scoreboard: list[dict]) -> dict:
    return {
        "teams": len(scoreboard),
        "avg_response_rate": _mean([t.get("response_rate", 0) for t in scoreboard]),
        "avg_on_time_rate": _mean([t.get("on_time_rate", 0) for t in scoreboard]),
        "avg_score_pct": _mean([t.get("score_pct", 0) for t in scoreboard]),
    }


def summarize_integrity(flagged: list[dict]) -> dict:
    return {
        "flagged_count": len(flagged),
        "clean": len(flagged) == 0,
        "cases": flagged,
    }


def summarize_protocol_attacks(events: list[dict]) -> dict:
    by_proto: dict[str, int] = {}
    by_register: dict[str, int] = {}
    total = 0
    for e in events:
        md = _as_dict(e.get("metadata"))
        proto = md.get("protocol")
        if not proto:
            continue
        total += 1
        by_proto[proto] = by_proto.get(proto, 0) + 1
        reg = md.get("register")
        if reg:
            by_register[reg] = by_register.get(reg, 0) + 1
    return {"total": total, "by_protocol": by_proto, "by_register": by_register}
