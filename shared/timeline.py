"""
통합 타임라인(Unified Exercise Timeline) — 순수 병합 로직
=========================================================
훈련 종료 후 사후검토(AAR)를 위해 흩어진 활동을 하나의 시간순 타임라인으로 모은다.
서로 다른 소스(이벤트/SIEM 알림/인시던트/인젝트)를 단일 정규화 엔트리로 변환한 뒤
발생 시각(ts) 오름차순으로 정렬한다.

설계 원칙:
  - I/O 없음(순수함수) → 이미 가져온 리스트만 받아 결정론적으로 병합(단위테스트 용이).
  - 실제 데이터를 이미 fetch 하는 곳(services/aar_report)이 이 함수에 넘겨 조립한다.

정규화 엔트리:
  {ts, kind, source, title, actor?, asset?, severity?, ref}
  - ts       : epoch(float) 또는 시각 없음(None) — None 은 정렬상 맨 뒤로.
  - kind      : event_type / "alert" / "incident" / "inject"
  - source    : "event_collector" | "siem" | "incident" | "injects"
  - title     : 사람이 읽는 한 줄 요약
  - actor?    : red|blue|system|team_id 등(있을 때만)
  - asset?    : 대상 자산/호스트(있을 때만)
  - severity? : 정수(SIEM 0~4) 또는 문자열(인시던트 critical..low)(있을 때만)
  - ref       : 원본 식별자(event_id/alert id/incident id/team_id)
"""
from __future__ import annotations

from datetime import datetime


def _to_epoch(v) -> float | None:
    """다양한 시각 표현을 epoch(float)로 정규화. 파싱 불가/누락 시 None.

    - float/int          : 그대로 epoch 초로 사용
    - datetime           : timestamp()
    - ISO8601 문자열      : fromisoformat 시도(…Z 는 +00:00 로 치환)
    """
    if v is None:
        return None
    if isinstance(v, bool):        # bool 은 int 하위형 → 시각으로 오인 방지
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, datetime):
        return v.timestamp()
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return None
        try:
            return float(s)        # "1699999999.0" 같은 숫자 문자열
        except ValueError:
            pass
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


def _entry(ts, kind, source, title, ref, actor=None, asset=None, severity=None) -> dict:
    """정규화 엔트리 생성 — 옵셔널 필드는 값이 있을 때만 포함(스키마 깔끔하게)."""
    e = {"ts": _to_epoch(ts), "kind": kind, "source": source,
         "title": title, "ref": ref}
    if actor is not None:
        e["actor"] = actor
    if asset is not None:
        e["asset"] = asset
    if severity is not None:
        e["severity"] = severity
    return e


def _from_events(events: list[dict]) -> list[dict]:
    """event_collector /replay/events → 정규화. shared/event_schema.py 참조."""
    out = []
    for e in events:
        et = e.get("event_type") or "event"
        asset = e.get("target_asset")
        title = f"{et} — {asset}" if asset else et
        out.append(_entry(
            ts=e.get("timestamp"), kind=et, source="event_collector",
            title=title, ref=e.get("event_id"),
            actor=e.get("actor"), asset=asset,
        ))
    return out


def _from_alerts(alerts: list[dict]) -> list[dict]:
    """siem /alerts → 정규화. services/siem/storage/alert_store.py 참조."""
    out = []
    for a in alerts:
        matched = a.get("matched_event")
        asset = matched.get("asset") if isinstance(matched, dict) else None
        out.append(_entry(
            ts=a.get("timestamp"), kind="alert", source="siem",
            title=a.get("title") or a.get("rule_id") or "alert",
            ref=a.get("id"), asset=asset, severity=a.get("severity"),
        ))
    return out


def _from_incidents(incidents: list[dict]) -> list[dict]:
    """incident /incidents → 정규화(생성 시각 기준). services/incident/main.py 참조."""
    out = []
    for i in incidents:
        out.append(_entry(
            ts=i.get("created_at"), kind="incident", source="incident",
            title=i.get("title") or "incident", ref=i.get("id"),
            actor="blue", asset=i.get("host"), severity=i.get("severity"),
        ))
    return out


def _from_injects(injects: list[dict]) -> list[dict]:
    """injects /injects/scoreboard → 팀별 대응 요약 정규화.

    스코어보드 행에는 시각이 없으므로 ts=None(정렬상 맨 뒤). services/injects/main.py 참조."""
    out = []
    for t in injects:
        team = t.get("team_id")
        rr = t.get("response_rate")
        title = f"인젝트 대응 요약: {team}" + (f" (응답률 {rr}%)" if rr is not None else "")
        out.append(_entry(
            ts=t.get("timestamp"), kind="inject", source="injects",
            title=title, ref=team, actor=team,
        ))
    return out


def _sort_key(entry: dict) -> tuple:
    """ts 오름차순 정렬 + 결정론적 tie-break.
    ts 없음(None)은 맨 뒤로 몰고, 동일 ts 는 (source, kind, ref, title)로 안정 정렬."""
    ts = entry.get("ts")
    has_ts = ts is not None
    return (
        0 if has_ts else 1,
        ts if has_ts else 0.0,
        str(entry.get("source") or ""),
        str(entry.get("kind") or ""),
        str(entry.get("ref") or ""),
        str(entry.get("title") or ""),
    )


def build_timeline(sources: dict) -> list[dict]:
    """이미 fetch 된 소스 리스트들을 하나의 시간순 타임라인으로 병합(순수·결정론적).

    sources = {
        "events":    [...],   # event_collector /replay/events
        "alerts":    [...],   # siem /alerts
        "incidents": [...],   # incident /incidents
        "injects":   [...],   # injects /injects/scoreboard
    }
    누락된 키는 빈 리스트로 취급한다.
    """
    entries: list[dict] = []
    entries += _from_events(sources.get("events") or [])
    entries += _from_alerts(sources.get("alerts") or [])
    entries += _from_incidents(sources.get("incidents") or [])
    entries += _from_injects(sources.get("injects") or [])
    entries.sort(key=_sort_key)
    return entries
