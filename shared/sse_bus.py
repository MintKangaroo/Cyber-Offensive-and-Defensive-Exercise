"""
SSE 허브(P0-4) — 폴링 제거용 인메모리 pub/sub
===============================================
상황판(대시보드 5종)이 3~5초 폴링으로 서버를 두드리던 것을, 서버가 이벤트를 밀어주는
구독 모델로 바꾸기 위한 최소 허브. FastAPI의 StreamingResponse(SSE)와 함께 쓴다.

설계 원칙:
  - 단일 허브: event_collector 가 모든 토픽(events/detections/scores/safety/phase_clock)을
    한 스트림으로 내보낸다. 상황판은 EventSource 하나만 열면 된다("상황판이 흔들리지 않게").
  - 느린 구독자 격리: 큐가 가득 차면 그 구독자만 이벤트를 흘리고(drop), publish 는 절대
    막히지 않는다 → 관전자 100명이 붙어도 이벤트 수집 경로가 느려지지 않음.
  - 리플레이: 링버퍼에 최근 N개를 보관, 재연결 시 Last-Event-ID 이후만 다시 보낸다.
  - 가시성: 역할·매치·지연은 visible_to()에서 순수함수로 결정(테스트 용이).

역할 가시성(visible_to):
  - instructor: 전부.
  - red/blue: 자기 match_id 의 메시지만(팀 정보 격리).
  - observer: match 제한 없음, 그러나 라이브 토픽(events/detections/scores)은 delay 초만큼
    지난 것만(관전자가 실시간 정보를 팀에 흘리는 것 방지). phase_clock/safety 는 지연 없음.
"""
from __future__ import annotations

import asyncio
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterable, Iterator, Optional

# 관전자 지연이 적용되는 라이브 토픽(그 외 phase_clock/safety 는 즉시 공개)
LIVE_TOPICS = frozenset({"events", "detections", "scores"})


@dataclass(frozen=True)
class Message:
    id: int
    topic: str
    data: dict[str, Any]


class SSEBus:
    def __init__(self, buffer_size: int = 1000):
        self._seq = 0
        self._buffer: deque[Message] = deque(maxlen=buffer_size)
        self._subs: set[asyncio.Queue] = set()

    def publish(self, topic: str, data: dict[str, Any]) -> int:
        """토픽에 메시지 발행. 순증하는 id 반환. 동기 함수(sync/async 어디서든 호출 가능)."""
        self._seq += 1
        msg = Message(id=self._seq, topic=topic, data=data)
        self._buffer.append(msg)
        for q in list(self._subs):
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                pass  # 느린 구독자만 이 메시지를 놓친다(재연결 시 Last-Event-ID 로 복구 가능)
        return self._seq

    def replay(self, last_id: int, topics: Optional[Iterable[str]]) -> list[Message]:
        """Last-Event-ID(last_id) 이후 메시지 중 topics 에 해당하는 것만 시간순으로."""
        tset = set(topics) if topics is not None else None
        return [m for m in self._buffer
                if m.id > last_id and (tset is None or m.topic in tset)]

    @contextmanager
    def subscription(self, maxsize: int = 1000) -> Iterator[asyncio.Queue]:
        q: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
        self._subs.add(q)
        try:
            yield q
        finally:
            self._subs.discard(q)

    @property
    def subscribers(self) -> int:
        return len(self._subs)

    @property
    def last_id(self) -> int:
        return self._seq


def visible_to(msg: Message, role: str, match_id: str, now: float,
               delay: float = 30.0) -> bool:
    """구독자(role, match_id)에게 이 메시지를 지금(now) 보여줘도 되는가."""
    if role in ("red", "blue"):
        # 팀은 자기 매치만. match_id 클레임이 없으면(미지정) 필터하지 않음(dev 편의).
        m = str(msg.data.get("match_id", "") or "")
        if match_id and m and m != match_id:
            return False
        return True
    if role == "observer":
        if msg.topic in LIVE_TOPICS:
            ts = float(msg.data.get("timestamp", 0) or 0)
            if ts and (now - ts) < delay:
                return False  # 아직 공개 지연 시간이 안 지남
        return True
    # instructor / 그 외(dev) → 전부
    return True
