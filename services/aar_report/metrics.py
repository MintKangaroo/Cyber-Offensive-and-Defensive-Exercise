"""
AAR 지표 계산 (27번 문서 1.1절)
==================================
Event Collector의 저장 이벤트를 입력으로 받아 MTTD/MTTR/탐지율/오탐률을 계산한다.
pydantic 비의존(순수 dict 리스트 입력) — 테스트하기 쉽게 설계.
"""
from __future__ import annotations
import json
from typing import Optional


def _metadata(event: dict) -> dict:
    """metadata는 소스에 따라 dict(메모리)일 수도, JSON 문자열(sqlite 역직렬화 전)일 수도 있다.
    event_collector /events는 문자열로 돌려주므로 여기서 항상 dict로 정규화한다
    (M6에서 alert_store/heatmap에 적용한 것과 같은 계열의 버그 방지)."""
    md = event.get("metadata")
    if isinstance(md, str):
        try:
            return json.loads(md)
        except (json.JSONDecodeError, TypeError):
            return {}
    return md if isinstance(md, dict) else {}


def _resolve_matched_attack(matched_id, by_id: dict, earliest_by_trace: dict) -> Optional[dict]:
    """탐지의 matched_event_id를 원 공격 이벤트로 해석.

    ⚠️ 소스별로 상관 키가 다르다: 같은 서비스 내부 이벤트는 원 event_id를 넣지만,
    SIEM의 blue_detection_success는 (다른 프로세스/DB라 event_id를 알 수 없어)
    trace_id를 matched_event_id에 넣는다(siem/api/main.py 참고). 그래서 event_id로만
    조인하면 SIEM 탐지가 전부 누락돼 MTTD/탐지율이 0/None으로 나온다.
    event_id → trace_id 순으로 해석한다(trace_id는 세션 공유이므로 그 세션의 가장 이른 공격)."""
    if matched_id is None:
        return None
    if matched_id in by_id:
        return by_id[matched_id]
    return earliest_by_trace.get(matched_id)


def compute_mttd(events: list[dict]) -> Optional[float]:
    """MTTD = mean(detection_ts - attack_ts).
    matched_event_id로 연결된 (공격, 탐지) 쌍을 전부 모아 평균.
    matched_event_id는 원 공격의 event_id 또는 trace_id를 가리킬 수 있다(위 헬퍼 참고)."""
    by_id = {e["event_id"]: e for e in events}
    attacks = [e for e in events if e.get("event_type") in ATTACK_EVENT_TYPES]
    earliest_by_trace: dict = {}
    for a in attacks:
        tid = a.get("trace_id")
        if tid and (tid not in earliest_by_trace or a["timestamp"] < earliest_by_trace[tid]["timestamp"]):
            earliest_by_trace[tid] = a
    diffs = []
    for e in events:
        matched_id = e.get("matched_event_id")
        attack = _resolve_matched_attack(matched_id, by_id, earliest_by_trace)
        if attack is not None and attack.get("event_id") != e.get("event_id"):
            diffs.append(e["timestamp"] - attack["timestamp"])
    if not diffs:
        return None
    return sum(diffs) / len(diffs)


def compute_mttr(events: list[dict]) -> Optional[float]:
    """MTTR = mean(dwell_sec) — asset_recovered 이벤트의 metadata.dwell_sec을 그대로 평균
    (recovery_watcher가 이미 계산해 넣어둠, 04번 문서 2절 구현체 참고)."""
    dwells = [
        _metadata(e)["dwell_sec"]
        for e in events
        if e.get("event_type") == "asset_recovered" and "dwell_sec" in _metadata(e)
    ]
    if not dwells:
        return None
    return sum(dwells) / len(dwells)


ATTACK_EVENT_TYPES = {"red_attack_started", "flag_exfiltrated", "red_objective_success"}


def compute_detection_rate(events: list[dict]) -> Optional[float]:
    """탐지율 = (matched_event_id가 있는 공격 수) / (전체 공격성 이벤트 수)."""
    attacks = [e for e in events if e.get("event_type") in ATTACK_EVENT_TYPES]
    if not attacks:
        return None
    # 탐지가 가리키는 키 집합(matched_event_id). SIEM은 trace_id를, 내부 이벤트는 event_id를 넣는다.
    detected_keys = {
        e.get("matched_event_id") for e in events
        if e.get("event_type") == "blue_detection_success" and e.get("matched_event_id")
    }
    # 한 공격은 자신의 event_id 또는 trace_id 중 하나라도 탐지에 걸리면 '탐지됨'으로 간주.
    detected_attacks = sum(
        1 for a in attacks
        if a.get("event_id") in detected_keys or a.get("trace_id") in detected_keys
    )
    return detected_attacks / len(attacks)


def _alert_is_background(alert: dict) -> bool:
    """감사 G-11: 배경(양성) 트래픽이 촉발한 알림인가.
    traffic_generator가 흘린 실 트래픽은 트윈 access 로그에 is_background=true로 라벨되고,
    파서가 이를 raw로 보존 + 'background_traffic' 태그로 노출한다 → SIEM 알림
    matched_event까지 전파된다. 그 알림은 ground truth상 오탐이다."""
    me = alert.get("matched_event")
    if not isinstance(me, dict):
        return False
    if isinstance(me.get("raw"), dict) and me["raw"].get("is_background"):
        return True
    tags = me.get("tags")
    return isinstance(tags, list) and "background_traffic" in tags


def compute_false_positive_rate(alerts: list[dict], noise_event_ids: set[str]) -> Optional[float]:
    """오탐률 = (ground truth상 노이즈인데 알림이 뜬 것) / (전체 알림).
    ground truth 소스 두 가지를 OR로 인정한다:
      1) 합성 노이즈 생성기(team_id="noise") 이벤트 id — 기존 경로(06번 문서 6절).
      2) 실 배경 트래픽(감사 G-11) — alert.matched_event의 is_background 라벨.
    alert의 matched_event 안에 원본 이벤트(source_event_id 또는 raw 라벨)가 있다고 가정."""
    if not alerts:
        return None
    fp_count = sum(
        1 for a in alerts
        if a.get("source_event_id") in noise_event_ids or _alert_is_background(a)
    )
    return fp_count / len(alerts)


def stealth_bonus_total(events: list[dict]) -> int:
    return sum(
        int(e.get("metadata", {}).get("bonus_points", 10))
        for e in events if e.get("event_type") == "red_stealth_bonus"
    )
