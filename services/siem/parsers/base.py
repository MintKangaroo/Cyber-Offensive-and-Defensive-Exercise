"""
Parser Registry (22번 문서 2절)
==================================
source_type -> 파서 함수 매핑. 등록된 파서가 실패(None 반환)하면 raw 그대로 감싸서
저장하고 parse_error 태그를 붙인다(로그 손실 없음).
"""
from __future__ import annotations
from typing import Callable, Optional
from datetime import datetime, timezone

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent.parent))
from shared.siem_schema import NormalizedEvent  # noqa: E402

from .twin import parse_twin_log_line
from .suricata import parse_suricata_line
from .pfsense import parse_pfsense_filterlog
from .zeek import parse_zeek_line

ParserFn = Callable[[str], Optional[NormalizedEvent]]

_REGISTRY: dict[str, ParserFn] = {
    "twin": parse_twin_log_line,
    "suricata": parse_suricata_line,
    "pfsense": parse_pfsense_filterlog,
    # zeek는 log_type(conn/dns/...)이 추가로 필요해서 별도 처리(아래 parse_any 참고)
}


def register(source_type: str, parser: ParserFn) -> None:
    _REGISTRY[source_type] = parser


def get_parser(source_type: str) -> Optional[ParserFn]:
    return _REGISTRY.get(source_type)


def _fallback_event(source_type: str, raw_text: str) -> NormalizedEvent:
    """모든 파서가 실패했을 때도 로그 자체는 잃지 않도록 최소 정보로 감싼다."""
    return NormalizedEvent(
        event_id=__import__("uuid").uuid4().hex,
        timestamp=datetime.now(timezone.utc),
        ingested_at=datetime.now(timezone.utc),
        source_type=source_type,
        severity=0,
        category="uncategorized",
        message=raw_text[:300],
        raw={"unparsed": raw_text},
        tags=["parse_error"],
    )


def parse_any(source_type: str, raw_text: str, zeek_log_type: Optional[str] = None) -> Optional[NormalizedEvent]:
    """반환값이 None이면 '저장할 이벤트가 아님'(Zeek 헤더/코멘트 라인 등)을 의미하고,
    파싱 실패로 인한 손실 방지가 필요한 경우는 호출부가 별도로 _fallback_event를 쓴다."""
    if source_type == "zeek":
        # 헤더/코멘트 라인은 에러가 아니라 정상적인 스킵 대상 -> fallback 감싸지 않음
        if raw_text.startswith("#"):
            parse_zeek_line(raw_text, zeek_log_type or "conn")  # 헤더면 내부적으로 캐싱됨
            return None
        event = parse_zeek_line(raw_text, zeek_log_type or "conn")
        if event is None:
            return None  # 헤더 캐시가 아직 없는 경우도 정상 스킵(다음 로테이션에서 헤더 옴)
        return event
    else:
        parser = get_parser(source_type)
        event = parser(raw_text) if parser else None
        if event is None:
            return _fallback_event(source_type, raw_text)  # 진짜 파싱 실패만 fallback 감싸기
        return event
