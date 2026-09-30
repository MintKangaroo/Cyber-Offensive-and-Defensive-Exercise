"""R-1 회귀: replay 페이지네이션 헬퍼가 커서를 따라 전량 순회하고, 원장 변경(409)을
ReplayChanged 로 올리며, 무한 fetchall 을 하지 않음을 고정한다(audit/102 R-1).
"""
from __future__ import annotations

import asyncio

import pytest

from shared.replay_client import (
    iter_event_pages_sync, fetch_all_events_async, ReplayChanged,
)


class FakeResp:
    def __init__(self, status_code=200, body=None):
        self.status_code = status_code
        self._body = body or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._body


def _paged_get(pages):
    """cursor 로 페이지를 돌려주는 가짜 sync get. 각 페이지는 (events, next_cursor, complete)."""
    def get(url, params=None, headers=None, timeout=None):
        cur = (params or {}).get("cursor", "")
        idx = int(cur) if cur else 0
        events, nxt, complete = pages[idx]
        return FakeResp(200, {"events": events, "next_cursor": nxt, "complete": complete})
    return get


def test_iter_pages_follows_cursor_to_completion():
    pages = [
        ([{"event_id": "a"}, {"event_id": "b"}], "1", False),
        ([{"event_id": "c"}], "", True),
    ]
    got = list(iter_event_pages_sync(_paged_get(pages), "http://ec", "s"))
    assert [len(p) for p in got] == [2, 1]
    ids = [e["event_id"] for page in got for e in page]
    assert ids == ["a", "b", "c"]


def test_iter_pages_raises_on_revision_change():
    def get(url, params=None, headers=None, timeout=None):
        return FakeResp(409)
    with pytest.raises(ReplayChanged):
        list(iter_event_pages_sync(get, "http://ec", "s"))


def test_fetch_all_events_async_accumulates_and_caps():
    class AClient:
        def __init__(self, pages):
            self.pages = pages
        async def get(self, url, params=None):
            cur = (params or {}).get("cursor", "")
            idx = int(cur) if cur else 0
            events, nxt, complete = self.pages[idx]
            return FakeResp(200, {"events": events, "next_cursor": nxt, "complete": complete})

    pages = [
        ([{"event_id": "a"}, {"event_id": "b"}], "1", False),
        ([{"event_id": "c"}, {"event_id": "d"}], "", True),
    ]
    all_ev = asyncio.run(fetch_all_events_async(AClient(pages), "http://ec", "s"))
    assert [e["event_id"] for e in all_ev] == ["a", "b", "c", "d"]
    # max_events 상한(소비자 메모리 방어)
    capped = asyncio.run(fetch_all_events_async(AClient(pages), "http://ec", "s", max_events=3))
    assert len(capped) == 3
