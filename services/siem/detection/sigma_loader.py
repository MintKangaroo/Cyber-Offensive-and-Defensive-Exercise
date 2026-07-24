"""
Sigma Loader (22번 문서 4절, M5.6)
=====================================
Sigma 표준의 서브셋(detection/condition/logsource)만 지원해 우리 Rule로 변환한다.
timeframe이 있으면 threshold로, 없으면 match로 매핑. 지원 못하는 필드(정규식 백레퍼런스,
복잡한 condition 연산자 등)는 예외 대신 warnings.warn으로 알리고 최대한 변환하거나 스킵한다.
"""
from __future__ import annotations
import warnings
from typing import Optional
import yaml

from .engine import Rule

_SIGMA_SEVERITY_MAP = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def load_sigma_yaml(path: str) -> Optional[Rule]:
    with open(path) as f:
        data = yaml.safe_load(f)
    return sigma_dict_to_rule(data, source_hint=path)


def sigma_dict_to_rule(data: dict, source_hint: str = "") -> Optional[Rule]:
    try:
        detection = data.get("detection", {})
        selection = detection.get("selection")
        condition = detection.get("condition", "selection")

        if selection is None:
            warnings.warn(f"[sigma_loader] {source_hint}: 'detection.selection' 없음, 스킵")
            return None

        if condition.strip() != "selection":
            warnings.warn(
                f"[sigma_loader] {source_hint}: condition '{condition}'은 미지원(단순 'selection'만 "
                f"지원). selection 필드만 사용해 최대한 변환합니다."
            )

        match = {_sigma_field_to_our_field(k): v for k, v in selection.items()}

        logsource = data.get("logsource", {})
        source_type = _map_logsource(logsource)

        severity = _SIGMA_SEVERITY_MAP.get(data.get("level", "medium"), 2)
        mitre = [tag.split(".")[-1].upper() for tag in data.get("tags", []) if tag.startswith("attack.t")]

        timeframe = detection.get("timeframe")
        if timeframe:
            warnings.warn(
                f"[sigma_loader] {source_hint}: timeframe이 있으나 threshold 자동변환은 미지원 — "
                f"match 규칙으로 단순화합니다(수동으로 threshold 규칙 작성 권장)."
            )

        return Rule(
            id=data.get("id", source_hint or "sigma-unknown"),
            title=data.get("title", "Imported Sigma Rule"),
            severity=severity,
            mitre=mitre,
            source_type=source_type,
            kind="match",
            match=match,
        )
    except Exception as e:
        warnings.warn(f"[sigma_loader] {source_hint}: 변환 실패({e}), 스킵")
        return None


def _sigma_field_to_our_field(sigma_field: str) -> str:
    """Sigma 필드명을 우리 NormalizedEvent 필드명으로 매핑(자주 쓰이는 것 위주)."""
    mapping = {
        "c-uri": "raw.uri",
        "cs-method": "raw.method",
        "sc-status": "status",
        "EventID": "raw.event_id",
    }
    return mapping.get(sigma_field, sigma_field)


def _map_logsource(logsource: dict) -> Optional[str]:
    product = logsource.get("product", "")
    category = logsource.get("category", "")
    if product in ("suricata", "zeek", "pfsense"):
        return product
    if category in ("firewall",):
        return "pfsense"
    if category in ("network_connection", "dns"):
        return "zeek"
    return None  # 알 수 없으면 전체 소스 대상(source_type=None)
