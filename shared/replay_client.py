"""event_collector 이벤트 원장을 메모리 안전하게 소비하는 페이지네이션 헬퍼.

배경(audit/102 R-1): `/replay/events` 무한 경로는 events 테이블 전체를 fetchall() 로 메모리에
적재해, 대용량 events.db(장시간 훈련 종료 시점) 에서 event_collector 를 OOM 시킨다. reconcile/AAR
이 그 경로를 호출하므로 훈련 종료 시 AAR PDF·정합성 검사가 무너진다.

이 헬퍼는 커서 기반 `/replay/page`(페이지당 상한 5000)를 순회해 event_collector 가 한 번에
한 페이지만 적재하게 한다. 소비자는 페이지 단위로 처리(집계)하거나 필요 시 누적한다.

`/replay/page` 는 순회 중 원장 revision 이 바뀌면 409 를 반환한다(진행 중 훈련). 그 경우
ReplayChanged 를 올려 호출자가 "검사 불가"로 정직하게 처리하게 한다.
"""
from __future__ import annotations

from typing import Any, Iterator

DEFAULT_PAGE_LIMIT = 2000
MAX_PAGES = 100_000  # 안전 상한(무한 루프 방지)


class ReplayChanged(Exception):
    """순회 중 원장이 변경됨(409). 재시작 필요."""


def iter_event_pages_sync(get, base_url: str, scenario_id: str, *,
                          headers: dict | None = None, timeout: float = 5.0,
                          page_limit: int = DEFAULT_PAGE_LIMIT) -> Iterator[list[dict[str, Any]]]:
    """동기 페이지 순회(주입된 httpx-like `get(url, params, headers, timeout)`).

    각 페이지의 events 리스트를 순차로 내보낸다. event_collector 는 페이지당 ≤ page_limit 행만 적재.
    """
    cursor = ""
    for _ in range(MAX_PAGES):
        resp = get(f"{base_url}/replay/page",
                   params={"scenario_id": scenario_id, "cursor": cursor, "limit": page_limit},
                   headers=headers or {}, timeout=timeout)
        if resp.status_code == 409:
            raise ReplayChanged("retained history changed mid-replay")
        resp.raise_for_status()
        body = resp.json()
        yield body.get("events", [])
        if body.get("complete", True):
            return
        cursor = body.get("next_cursor", "")
        if not cursor:
            return


async def fetch_all_events_async(client, base_url: str, scenario_id: str, *,
                                 page_limit: int = DEFAULT_PAGE_LIMIT,
                                 max_events: int | None = None) -> list[dict[str, Any]]:
    """비동기: 전체 이벤트를 페이지네이션으로 모아 반환(event_collector 는 페이지당만 적재).

    max_events 를 주면 그 상한까지만 모으고 멈춘다(소비자 메모리 방어, None=무제한).
    """
    events: list[dict[str, Any]] = []
    cursor = ""
    for _ in range(MAX_PAGES):
        resp = await client.get(f"{base_url}/replay/page",
                                params={"scenario_id": scenario_id, "cursor": cursor,
                                        "limit": page_limit})
        if resp.status_code == 409:
            raise ReplayChanged("retained history changed mid-replay")
        resp.raise_for_status()
        body = resp.json()
        events.extend(body.get("events", []))
        if max_events is not None and len(events) >= max_events:
            return events[:max_events]
        if body.get("complete", True):
            return events
        cursor = body.get("next_cursor", "")
        if not cursor:
            return events
    return events
