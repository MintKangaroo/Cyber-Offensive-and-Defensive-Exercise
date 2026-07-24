"""
pfSense filterlog 파서 (22번 문서 2절, M5.3 / 26번 문서 5절)
================================================================
filterlog CSV 필드: rule#,sub#,anchor,tracker,iface,reason,action,dir,proto,...
action="block"/"pass" -> severity 2/0.
26번 문서 5절의 시뮬레이터(실제 pfSense VM 없이 이 포맷을 흉내내는 스크립트)가 보내는
로그도 동일하게 이 파서로 처리된다.
"""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Optional

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent.parent))
from shared.siem_schema import NormalizedEvent, NetEndpoint  # noqa: E402

try:
    from ulid import ULID
except ImportError:
    ULID = None


def _new_id() -> str:
    if ULID is not None:
        try:
            return str(ULID())
        except Exception:
            pass
    import uuid
    return uuid.uuid4().hex


# filterlog 필수 컬럼(단순화 버전 - 실제 pfSense는 프로토콜별로 필드 수가 다름)
_FIELDS = [
    "rule_num", "sub_rule", "anchor", "tracker", "iface", "reason", "action",
    "direction", "ip_version", "tos", "ecn", "ttl", "id", "offset", "flags",
    "proto_id", "proto_text", "length", "src_ip", "dst_ip", "src_port", "dst_port",
]


def parse_pfsense_filterlog(raw_line: str) -> Optional[NormalizedEvent]:
    """filterlog은 보통 syslog 페이로드 뒤에 CSV로 붙는다: '<prio>...filterlog: 1,,,...,block,...'
    'filterlog:' 뒤부터를 CSV로 파싱한다."""
    marker = "filterlog:"
    idx = raw_line.find(marker)
    if idx == -1:
        return None
    csv_part = raw_line[idx + len(marker):].strip()
    values = csv_part.split(",")
    if len(values) < 7:  # action까지는 최소로 있어야 함(뒤 프로토콜별 필드는 없어도 파싱 시도)
        return None

    row = dict(zip(_FIELDS, values))
    action = row.get("action", "").lower()

    try:
        return NormalizedEvent(
            event_id=_new_id(),
            timestamp=datetime.now(timezone.utc),  # filterlog 자체엔 별도 타임스탬프 필드가 없어 수신시각 사용
            ingested_at=datetime.now(timezone.utc),
            source_type="pfsense",
            source_ip=row.get("src_ip"),
            asset=None,
            severity=2 if action == "block" else 0,
            category="firewall",
            action="blocked" if action == "block" else "allowed",
            src=NetEndpoint(ip=row.get("src_ip"), port=_safe_int(row.get("src_port"))),
            dst=NetEndpoint(ip=row.get("dst_ip"), port=_safe_int(row.get("dst_port"))),
            network={"proto": row.get("proto_text"), "iface": row.get("iface"), "direction": row.get("direction")},
            message=f"pfSense {action} {row.get('src_ip')}:{row.get('src_port')} -> "
                    f"{row.get('dst_ip')}:{row.get('dst_port')} ({row.get('proto_text')})",
            raw=row,
            tags=["pfsense"],
        )
    except Exception:
        return None


def _safe_int(v: Optional[str]) -> Optional[int]:
    try:
        return int(v) if v else None
    except (ValueError, TypeError):
        return None
