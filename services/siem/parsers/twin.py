"""
트윈 구조화 로그 파서 (22번 문서 2절, M5.1)
=============================================
shared/siem_access_log.py가 남긴 JSON 한 줄을 NormalizedEvent(ECS-lite)로 변환.
가장 먼저 구현하는 파서 — 이미 구조화 JSON이라 다른 소스보다 훨씬 쉽다.
"""
from __future__ import annotations
import json
from datetime import datetime, timezone
from typing import Optional

try:
    from ulid import ULID  # python-ulid 패키지(pip install python-ulid). 없으면 uuid로 폴백
except ImportError:
    ULID = None

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent.parent))
from shared.siem_schema import NormalizedEvent, NetEndpoint  # noqa: E402

# 트윈의 응답 status_code -> severity 매핑표 (22번 문서 2절 twin 파서 스펙)
def _severity_from_status(status: Optional[int], vuln_id: Optional[str]) -> int:
    if status is None:
        return 1
    if vuln_id and status < 400:
        # 취약점 매핑 경로인데 정상 응답(200) -> 공격이 실제로 먹혔을 가능성 -> high
        return 3
    if status >= 500:
        return 3
    if status in (401, 403):
        return 2
    return 0


def _new_id() -> str:
    if ULID is not None:
        try:
            return str(ULID())
        except Exception:
            pass
    import uuid
    return uuid.uuid4().hex  # ULID 라이브러리 없으면 uuid로 폴백(시간정렬 특성만 없음)


def parse_twin_log_line(raw_line: str, source_ip_fallback: Optional[str] = None) -> Optional[NormalizedEvent]:
    """트윈 access log의 JSON 한 줄을 파싱. 실패 시 None(호출부가 raw 그대로 보존 처리)."""
    try:
        data = json.loads(raw_line)
    except json.JSONDecodeError:
        return None

    try:
        ts = data.get("ts")
        timestamp = datetime.fromtimestamp(ts, tz=timezone.utc) if ts else datetime.now(timezone.utc)
        vuln_id = data.get("vuln_id")
        status = data.get("status")

        return NormalizedEvent(
            event_id=_new_id(),
            timestamp=timestamp,
            ingested_at=datetime.now(timezone.utc),
            source_type="twin",
            source_ip=data.get("src_ip") or source_ip_fallback,
            host=data.get("asset"),
            asset=data.get("asset"),
            severity=_severity_from_status(status, vuln_id),
            category="web",
            action="allowed" if (status and status < 400) else "blocked",
            src=NetEndpoint(ip=data.get("src_ip") or source_ip_fallback),
            network={},
            signature=f"TWIN-{vuln_id}" if vuln_id else None,
            mitre=[],  # vuln_catalog.json과 조인해서 채우는 건 enrich 단계(다음 확장)
            trace_id=data.get("trace_id"),
            vuln_id=vuln_id,
            team_id=data.get("team_id"),
            message=(f"{data.get('method','?')} {data.get('endpoint','?')} -> {status} "
                    f"(team={data.get('team_id','?')}, vuln={vuln_id or 'n/a'})"),
            raw=data,
            tags=["twin_access_log"],
        )
    except Exception:
        return None  # 필드 이상 등 예기치 못한 실패도 안전하게 None(무한루프 방지)
