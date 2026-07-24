"""
Noise Generator (06번 문서 5절, M5.6)
========================================
정상 사용자 행동(로그인 성공, 정상 텔레메트리 조회, 헬스체크)을 eps 비율로 흘려보내
공격 신호를 노이즈 속에 숨긴다. 업무시간대(9~18시)에는 가중치를 높여 현실적인 트래픽
패턴을 흉내낸다.
"""
from __future__ import annotations
import asyncio
import random
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Awaitable


@dataclass
class NoiseEvent:
    source_type: str
    asset: str
    endpoint: str
    status: int
    src_ip: str
    team_id: str
    message: str
    timestamp: float = field(default_factory=time.time)
    is_noise: bool = True  # ground truth 라벨(06번 문서 6절 오탐 트리아지 훈련용)


_NORMAL_ENDPOINTS = [
    ("ground_station", "/api/telemetry", 200),
    ("power_plant", "/api/plc/read", 200),
    ("defense_network", "/health", 200),
]
_NORMAL_SRC_IPS = [f"10.50.0.{i}" for i in range(1, 20)]  # 훈련장 내부 '정상' 사용자 대역(더미)


def _business_hours_weight(dt: datetime) -> float:
    """9~18시는 1.0, 그 외 시간은 0.3 — 업무시간대 트래픽이 더 많은 현실적 패턴."""
    return 1.0 if 9 <= dt.hour < 18 else 0.3


class NoiseGenerator:
    def __init__(self, base_eps: float, on_event: Callable[[NoiseEvent], Awaitable[None]]):
        self.base_eps = base_eps
        self.on_event = on_event
        self._running = False

    def _generate_one(self) -> NoiseEvent:
        asset, endpoint, status = random.choice(_NORMAL_ENDPOINTS)
        return NoiseEvent(
            source_type="twin",
            asset=asset,
            endpoint=endpoint,
            status=status,
            src_ip=random.choice(_NORMAL_SRC_IPS),
            team_id="noise",
            message=f"normal traffic: {endpoint}",
        )

    async def run_forever(self) -> None:
        self._running = True
        while self._running:
            now = datetime.now()
            weight = _business_hours_weight(now)
            effective_eps = max(0.1, self.base_eps * weight)
            interval = 1.0 / effective_eps
            await self.on_event(self._generate_one())
            await asyncio.sleep(interval)

    def stop(self) -> None:
        self._running = False
