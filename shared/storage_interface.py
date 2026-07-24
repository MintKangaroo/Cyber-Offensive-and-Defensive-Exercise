"""
B0 계약: 저장소 인터페이스
============================
SIEM 저장 계층을 추상화. MVP는 SQLite(FTS5), 운영은 OpenSearch로 교체 가능하게.
Ingestion/Detection/API는 이 인터페이스에만 의존한다(구체 구현 비의존).

이 파일은 B0만 수정한다.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, Optional
from datetime import datetime

from .siem_schema import NormalizedEvent


class SearchQuery:
    """검색 파라미터 컨테이너(백엔드 중립)."""
    def __init__(
        self,
        text: Optional[str] = None,
        source_type: Optional[str] = None,
        asset: Optional[str] = None,
        severity_min: Optional[int] = None,
        mitre: Optional[str] = None,
        time_from: Optional[datetime] = None,
        time_to: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ):
        self.text = text
        self.source_type = source_type
        self.asset = asset
        self.severity_min = severity_min
        self.mitre = mitre
        self.time_from = time_from
        self.time_to = time_to
        self.limit = limit
        self.offset = offset


class StorageBackend(ABC):
    """SIEM 저장소 백엔드 계약. 구현체: SqliteBackend(MVP), OpenSearchBackend(운영)."""

    @abstractmethod
    async def index(self, event: NormalizedEvent) -> None:
        """단일 정규화 이벤트 저장. event_id 기준 멱등(중복 무시)."""
        ...

    @abstractmethod
    async def bulk_index(self, events: list[NormalizedEvent]) -> int:
        """배치 저장. 저장된 신규 건수 반환."""
        ...

    @abstractmethod
    async def search(self, query: SearchQuery) -> list[NormalizedEvent]:
        """조건 검색(전문검색+필터). 시간 역순 정렬."""
        ...

    @abstractmethod
    async def aggregate(self, field: str, query: SearchQuery) -> dict[str, int]:
        """필드별 집계(예: source_type별 카운트, severity 분포)."""
        ...

    @abstractmethod
    async def count(self, query: SearchQuery) -> int:
        ...

    @abstractmethod
    async def health(self) -> dict[str, Any]:
        """백엔드 상태(연결/문서수/디스크 등)."""
        ...
