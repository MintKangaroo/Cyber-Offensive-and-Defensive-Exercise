"""
Background Traffic Driver (감사 §3 G-11)
========================================
`profile.plan_request`가 고른 양성 요청을 실제 HTTP로 트윈에 쏘는 비동기 루프.
쏘는 순간 트윈의 access 미들웨어가 실 로그를 남기므로, 여기서는 응답을 신경 쓰지
않는다(best-effort: 트윈이 재기동 중이거나 격리돼 5xx여도 계속 돈다).

모든 배경 요청에 다음을 붙인다:
  * `X-Background-Traffic: 1` — 미들웨어가 이걸 보고 access 로그에 is_background=true를
    찍는다 → AAR 오탐률의 ground truth.
  * `X-Forwarded-For: <내부 사용자 IP>` — 감사 4.1 XFF 우선 로직에 따라 미들웨어가 이걸
    src_ip로 기록(배경 트래픽 출처를 공격자 IP와 구분).
  * `X-Team-Id: noise` — 배경 트래픽은 특정 팀에 귀속되지 않는다.
  * benign User-Agent — 로그에서 사람이 눈으로도 배경임을 식별.
"""
from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import httpx

from .profile import BACKGROUND_USER_AGENT, PlannedRequest, TrafficProfile, plan_request


@dataclass
class DriverStats:
    started_at: Optional[float] = None
    sent: int = 0            # 요청을 성공적으로 전송(응답 수신)한 횟수
    errors: int = 0          # 연결 실패/타임아웃 등(트윈 다운/재기동 중일 수 있음)
    by_asset: dict[str, int] = field(default_factory=dict)
    last_status: Optional[int] = None
    last_target: Optional[str] = None

    def as_dict(self) -> dict:
        uptime = (time.time() - self.started_at) if self.started_at else 0.0
        return {
            "started_at": self.started_at,
            "uptime_sec": round(uptime, 1),
            "sent": self.sent,
            "errors": self.errors,
            "by_asset": dict(self.by_asset),
            "last_status": self.last_status,
            "last_target": self.last_target,
            "effective_eps": round(self.sent / uptime, 3) if uptime > 0 else None,
        }


BACKGROUND_HEADERS_BASE = {
    "X-Background-Traffic": "1",
    "X-Team-Id": "noise",
    "User-Agent": BACKGROUND_USER_AGENT,
}


class TrafficDriver:
    def __init__(self, profile: TrafficProfile, rng: Optional[random.Random] = None,
                 timeout: float = 3.0):
        self.profile = profile
        self.rng = rng or random.Random()
        self.timeout = timeout
        self.stats = DriverStats()
        self._running = False
        self._client: Optional[httpx.AsyncClient] = None

    async def _send_one(self, req: PlannedRequest) -> None:
        assert self._client is not None
        headers = dict(BACKGROUND_HEADERS_BASE)
        headers["X-Forwarded-For"] = req.src_ip
        try:
            if req.method.upper() == "POST":
                resp = await self._client.post(req.url, json=req.body or {}, headers=headers)
            else:
                resp = await self._client.get(req.url, headers=headers)
            self.stats.sent += 1
            self.stats.last_status = resp.status_code
            self.stats.by_asset[req.asset] = self.stats.by_asset.get(req.asset, 0) + 1
        except (httpx.HTTPError, OSError):
            # 트윈이 재기동/격리/네트워크 지연이어도 배경 트래픽은 멈추지 않는다.
            self.stats.errors += 1
        finally:
            self.stats.last_target = f"{req.asset}{req.path}"

    async def run_forever(self) -> None:
        self._running = True
        self.stats.started_at = time.time()
        self._client = httpx.AsyncClient(timeout=self.timeout)
        try:
            while self._running:
                now = datetime.now()
                req = plan_request(self.profile, self.rng)
                if req is not None:
                    await self._send_one(req)
                await asyncio.sleep(self.profile.interval_seconds(now))
        finally:
            if self._client is not None:
                await self._client.aclose()
                self._client = None

    def stop(self) -> None:
        self._running = False

    @property
    def running(self) -> bool:
        return self._running
