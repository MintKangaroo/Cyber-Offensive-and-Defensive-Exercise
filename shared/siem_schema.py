"""
B0 계약: SIEM 정규화 이벤트 스키마 (ECS-lite)
================================================
SIEM의 수집→정규화 계층이 모든 소스(트윈/Suricata/Zeek/pfSense)를
이 단일 스키마로 변환한다. 저장소·탐지엔진·API·대시보드가 이 계약을 공유.

이 파일은 B0만 수정한다.
"""

from __future__ import annotations
from typing import Optional, Any
from datetime import datetime
from pydantic import BaseModel, Field

SIEM_SCHEMA_VERSION = "1.0.0"


class NetEndpoint(BaseModel):
    ip: Optional[str] = None
    port: Optional[int] = None
    geo: Optional[str] = None      # 국가/도시(enrichment)
    asn: Optional[str] = None


class NormalizedEvent(BaseModel):
    event_id: str                  # ULID 권장(시간정렬+dedup)
    timestamp: datetime            # 이벤트 발생 시각(파싱됨)
    ingested_at: datetime          # 수집 시각
    source_type: str               # "suricata"|"zeek"|"pfsense"|"twin"|"syslog"
    source_ip: Optional[str] = None
    host: Optional[str] = None
    asset: Optional[str] = None    # ground_station|power_plant|defense_network|dmz
    severity: int = 0              # 0(info)~4(critical) 정규화
    category: str = "uncategorized"  # network|intrusion|firewall|auth|web|ics...
    action: Optional[str] = None   # allowed|blocked|alert|detected

    src: Optional[NetEndpoint] = None
    dst: Optional[NetEndpoint] = None
    network: dict[str, Any] = Field(default_factory=dict)  # protocol,bytes,packets,direction

    signature: Optional[str] = None
    signature_id: Optional[str] = None
    mitre: list[str] = Field(default_factory=list)

    # Live Fire 상관용(트윈 소스일 때)
    trace_id: Optional[str] = None
    vuln_id: Optional[str] = None
    team_id: Optional[str] = None

    message: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)  # 원본 보존(무결성)
    tags: list[str] = Field(default_factory=list)
    schema_version: str = SIEM_SCHEMA_VERSION


# severity 정규화 매핑(파서가 참조하는 단일 기준)
SEVERITY_MAP = {
    "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}

# source_type → 기본 category(파서 기본값, 개별 이벤트가 덮어쓸 수 있음)
DEFAULT_CATEGORY = {
    "suricata": "intrusion",
    "zeek": "network",
    "pfsense": "firewall",
    "twin": "web",
    "syslog": "uncategorized",
}
