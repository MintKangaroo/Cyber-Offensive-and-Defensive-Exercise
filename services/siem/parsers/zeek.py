"""
Zeek 로그 파서 (22번 문서 2절, M5.3)
======================================
Zeek 로그는 탭 구분 텍스트이고, 파일 맨 위에 '#fields <컬럼명...>' 헤더가 있다.
이 헤더를 먼저 캐싱해두고 이후 데이터 라인을 그 매핑으로 파싱한다.
log_type별로 헤더 캐시를 따로 유지(conn/dns/http/ssl 파일이 다르므로).
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


# log_type -> 마지막으로 캐싱된 #fields 컬럼 순서
_field_cache: dict[str, list[str]] = {}


def reset_field_cache(log_type: Optional[str] = None) -> None:
    """테스트/재시작 시 캐시 초기화."""
    if log_type:
        _field_cache.pop(log_type, None)
    else:
        _field_cache.clear()


def _try_cache_header(log_type: str, line: str) -> bool:
    """'#fields\tts\tuid\t...' 형태의 헤더 라인이면 캐싱하고 True 반환."""
    if line.startswith("#fields"):
        parts = line.split("\t")
        _field_cache[log_type] = parts[1:]  # 첫 토큰 '#fields' 제외
        return True
    return False


def parse_zeek_line(raw_line: str, log_type: str) -> Optional[NormalizedEvent]:
    """log_type: 'conn'|'dns'|'http'|'ssl'|'notice'. 헤더 라인이면 캐싱만 하고 None 반환
    (호출부가 None을 '이 라인은 저장할 이벤트가 아님'으로 처리하면 된다)."""
    if raw_line.startswith("#"):
        _try_cache_header(log_type, raw_line)
        return None

    fields = _field_cache.get(log_type)
    if not fields:
        return None  # 헤더를 아직 못 봤으면 컬럼 의미를 알 수 없어 스킵(다음 로테이션에서 헤더부터 다시 옴)

    values = raw_line.split("\t")
    if len(values) != len(fields):
        return None  # 컬럼 수 불일치(형식 오류) -> 안전하게 스킵
    row = dict(zip(fields, values))

    def _get(key: str) -> Optional[str]:
        v = row.get(key)
        return None if v in (None, "-", "(empty)") else v

    try:
        ts_raw = _get("ts")
        timestamp = datetime.fromtimestamp(float(ts_raw), tz=timezone.utc) if ts_raw else datetime.now(timezone.utc)

        src_ip = _get("id.orig_h")
        src_port = _get("id.orig_p")
        dst_ip = _get("id.resp_h")
        dst_port = _get("id.resp_p")

        message_map = {
            "conn": f"conn {src_ip}:{src_port} -> {dst_ip}:{dst_port} proto={_get('proto')} "
                   f"dur={_get('duration')} bytes={_get('orig_bytes')}/{_get('resp_bytes')}",
            "dns": f"dns query={_get('query')} answers={_get('answers')}",
            "http": f"http {_get('method')} {_get('host')}{_get('uri')} status={_get('status_code')}",
            "ssl": f"ssl {src_ip}:{src_port} -> {dst_ip}:{dst_port} server_name={_get('server_name')}",
            "notice": f"notice {_get('note')}: {_get('msg')}",
        }

        return NormalizedEvent(
            event_id=_new_id(),
            timestamp=timestamp,
            ingested_at=datetime.now(timezone.utc),
            source_type="zeek",
            source_ip=src_ip,
            asset=None,
            severity=3 if log_type == "notice" else 0,
            category="network",
            action=None,
            src=NetEndpoint(ip=src_ip, port=int(src_port) if src_port else None),
            dst=NetEndpoint(ip=dst_ip, port=int(dst_port) if dst_port else None),
            network={"proto": _get("proto"), "log_type": log_type},
            message=message_map.get(log_type, f"{log_type}: {row}"),
            raw=row,
            tags=["zeek", log_type],
        )
    except Exception:
        return None
