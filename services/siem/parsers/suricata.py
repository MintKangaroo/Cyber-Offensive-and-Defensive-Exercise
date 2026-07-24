"""
Suricata eve.json 파서 (22번 문서 2절, M5.3)
================================================
eve.json 한 줄(JSON)을 event_type 필드로 분기해 파싱한다:
  - "alert": signature/signature_id/severity
  - "flow": network.bytes/packets/direction
  - "dns"/"http": 카테고리=network, message에 요약
"""
from __future__ import annotations
import json
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


# Suricata alert.severity(1=high,2=medium,3=low) -> 우리 severity(0~4, 높을수록 심각)로 역산
_SURICATA_SEVERITY_MAP = {1: 3, 2: 2, 3: 1}


def parse_suricata_line(raw_line: str) -> Optional[NormalizedEvent]:
    try:
        data = json.loads(raw_line)
    except json.JSONDecodeError:
        return None

    try:
        ts_str = data.get("timestamp")
        timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00")) if ts_str else datetime.now(timezone.utc)
        event_type = data.get("event_type", "unknown")

        src = NetEndpoint(ip=data.get("src_ip"), port=data.get("src_port"))
        dst = NetEndpoint(ip=data.get("dest_ip"), port=data.get("dest_port"))

        signature = None
        signature_id = None
        severity = 1
        mitre: list[str] = []
        category = "network"
        message = f"suricata {event_type}"

        if event_type == "alert":
            alert = data.get("alert", {})
            signature = alert.get("signature")
            signature_id = str(alert.get("signature_id", ""))
            severity = _SURICATA_SEVERITY_MAP.get(alert.get("severity", 3), 1)
            category = "intrusion"
            message = f"Suricata alert: {signature}"
        elif event_type == "flow":
            flow = data.get("flow", {})
            category = "network"
            message = (f"flow {src.ip}:{src.port} -> {dst.ip}:{dst.port} "
                      f"bytes={flow.get('bytes_toserver', 0)+flow.get('bytes_toclient', 0)}")
        elif event_type in ("dns", "http"):
            category = "network"
            detail = data.get(event_type, {})
            message = f"{event_type}: {json.dumps(detail)[:200]}"

        return NormalizedEvent(
            event_id=_new_id(),
            timestamp=timestamp,
            ingested_at=datetime.now(timezone.utc),
            source_type="suricata",
            source_ip=data.get("src_ip"),
            host=data.get("host"),
            asset=None,  # asset 태깅은 enrich 단계(IP->asset 매핑)에서 채움
            severity=severity,
            category=category,
            action=data.get("alert", {}).get("action") if event_type == "alert" else None,
            src=src,
            dst=dst,
            network={"proto": data.get("proto"), "event_type": event_type},
            signature=signature,
            signature_id=signature_id,
            mitre=mitre,
            message=message,
            raw=data,
            tags=["suricata"],
        )
    except Exception:
        return None
