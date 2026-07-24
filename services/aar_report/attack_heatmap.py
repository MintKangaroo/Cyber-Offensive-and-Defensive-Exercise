"""
AAR ATT&CK 히트맵 (27번 문서 1.2절)
=====================================
이번 훈련에서 실제 발생한 이벤트의 mitre 태그를 모아 기술별 '탐지 성공 여부'를 판정.
단순 발생 여부가 아니라, 그 기술에 대응하는 탐지 알림이 있었는지가 covered의 기준.
"""
from __future__ import annotations
import json


def _as_list(value) -> list:
    """mitre 필드를 리스트로 정규화.

    소스마다 직렬화가 달라서(event_collector/siem이 JSON 문자열로 주는 경우가 있음)
    문자열이면 파싱한다. 이 정규화가 없으면 '["T1234"]' 문자열을 그대로 순회해
    기술 ID가 개별 문자('[','"','T'...)로 쪼개지는 버그가 난다.
    """
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else [parsed]
        except (json.JSONDecodeError, TypeError):
            return [value]
    return [value]


def _event_mitre(e: dict) -> list:
    md = e.get("metadata")
    if isinstance(md, str):
        try:
            md = json.loads(md)
        except (json.JSONDecodeError, TypeError):
            md = {}
    md = md if isinstance(md, dict) else {}
    return _as_list(md.get("mitre")) or _as_list(e.get("mitre"))


def build_heatmap(events: list[dict], alerts: list[dict]) -> dict[str, dict]:
    """
    events: Event Collector 이벤트(공격 이벤트에 mitre 태그가 있다고 가정하지 않고,
            metadata.mitre 또는 vuln_catalog 조인 결과로 들어온다고 가정)
    alerts: SIEM 알림(각 알림은 mitre 리스트를 가짐, 그 알림이 어떤 event_id를 잡았는지도 포함)

    반환: {technique_id: {"occurred": bool, "detected": bool, "rule_ids": [...]}}
    """
    heatmap: dict[str, dict] = {}

    # 1) 이번 훈련에서 실제 사용된 기술(공격 이벤트의 mitre 태그)
    for e in events:
        for technique in _event_mitre(e):
            heatmap.setdefault(technique, {"occurred": False, "detected": False, "rule_ids": []})
            heatmap[technique]["occurred"] = True

    # 2) 탐지된 기술(알림의 mitre 태그)
    for a in alerts:
        for technique in _as_list(a.get("mitre")):
            heatmap.setdefault(technique, {"occurred": False, "detected": False, "rule_ids": []})
            heatmap[technique]["detected"] = True
            rule_id = a.get("rule_id")
            if rule_id and rule_id not in heatmap[technique]["rule_ids"]:
                heatmap[technique]["rule_ids"].append(rule_id)

    return heatmap


def uncovered_techniques(heatmap: dict[str, dict]) -> list[str]:
    """발생했지만 탐지되지 않은 기술 목록(갭 분석)."""
    return [t for t, info in heatmap.items() if info["occurred"] and not info["detected"]]
