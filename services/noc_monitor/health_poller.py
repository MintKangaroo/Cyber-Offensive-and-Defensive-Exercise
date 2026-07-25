"""
Health Poller
===============
각 트윈의 /health를 주기적으로 폴링해 uptime%/latency/에러율을 계산한다.
이 결과를 Recovery Watcher(04번 2절, asset_recovered 판정)와 NOC API(대시보드)가 함께 구독한다.
단일 구현으로 두 목적을 만족시켜 중복을 피한다.
"""
from __future__ import annotations
import os
import asyncio
import time
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Awaitable, Optional

import httpx

DB_PATH = Path(os.environ.get("DATA_DIR", str(Path(__file__).parent))) / "health_history.db"  # 볼륨 영속(P0-3)
POLL_INTERVAL_SEC = 5
HISTORY_WINDOW_SEC = 3600     # 1시간 업타임% 계산 윈도우


@dataclass
class HealthSample:
    asset: str
    timestamp: float
    up: bool
    latency_ms: Optional[float] = None
    status_code: Optional[int] = None


@dataclass
class HealthState:
    """자산별 실시간 상태(메모리 캐시, DB는 이력용)."""
    up: bool = True
    consecutive_ok: int = 0        # Recovery Watcher가 "3회 연속 정상" 판정에 사용
    last_check: float = field(default_factory=time.time)
    last_latency_ms: Optional[float] = None
    was_ever_down: bool = False     # compromised 이후 복구 판정 조건(04번 2절)


class HealthPoller:
    def __init__(self, targets: dict[str, str]):
        """targets: {asset_name: health_url}"""
        self.targets = targets
        self.state: dict[str, HealthState] = {a: HealthState() for a in targets}
        self._recovery_callbacks: list[Callable[[str], Awaitable[None]]] = []
        self._init_db()

    def _init_db(self) -> None:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS health_samples (
                asset TEXT, timestamp REAL, up INTEGER, latency_ms REAL, status_code INTEGER
            )
            """
        )
        conn.commit()
        conn.close()

    def on_recovery_condition_met(self, callback: Callable[[str], Awaitable[None]]) -> None:
        """asset이 '연속 3회 정상 + 이전에 다운 이력 있음' 조건을 만족할 때 호출될 콜백 등록.
        (Recovery Watcher가 여기 연결해 asset_recovered 이벤트를 발행한다.)"""
        self._recovery_callbacks.append(callback)

    async def _poll_once(self, asset: str, url: str) -> HealthSample:
        start = time.time()
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                r = await client.get(url)
            latency_ms = (time.time() - start) * 1000
            up = r.status_code < 500
            return HealthSample(asset, time.time(), up, latency_ms, r.status_code)
        except httpx.HTTPError:
            return HealthSample(asset, time.time(), False, None, None)

    async def _record(self, sample: HealthSample) -> None:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO health_samples (asset, timestamp, up, latency_ms, status_code) VALUES (?, ?, ?, ?, ?)",
            (sample.asset, sample.timestamp, int(sample.up), sample.latency_ms, sample.status_code),
        )
        conn.commit()
        conn.close()

    async def _update_state(self, sample: HealthSample) -> None:
        st = self.state[sample.asset]
        st.last_check = sample.timestamp
        st.last_latency_ms = sample.latency_ms

        if sample.up:
            st.consecutive_ok += 1
        else:
            st.consecutive_ok = 0
            st.was_ever_down = True   # 다운 이력 기록(복구 판정의 전제조건, 04번 2절)

        st.up = sample.up

        # 복구 조건: 이전에 다운된 적 있고, 지금 3회 연속 정상
        if st.was_ever_down and st.consecutive_ok >= 3:
            for cb in self._recovery_callbacks:
                await cb(sample.asset)
            st.was_ever_down = False   # 한 번 복구 처리 후 리셋(재침해 시 다시 트리거되도록)

    async def poll_forever(self) -> None:
        while True:
            for asset, url in self.targets.items():
                sample = await self._poll_once(asset, url)
                await self._record(sample)
                await self._update_state(sample)
            await asyncio.sleep(POLL_INTERVAL_SEC)

    # ---- NOC API가 조회하는 조회 메서드 ----

    def current_status(self) -> dict[str, dict]:
        now = time.time()
        return {
            asset: {
                "up": st.up,
                "latency_ms": st.last_latency_ms,
                "last_check_ago_sec": round(now - st.last_check, 1),
                "consecutive_ok": st.consecutive_ok,
            }
            for asset, st in self.state.items()
        }

    def uptime_pct(self, asset: str, window_sec: int = HISTORY_WINDOW_SEC) -> float:
        conn = sqlite3.connect(DB_PATH)
        since = time.time() - window_sec
        rows = conn.execute(
            "SELECT up FROM health_samples WHERE asset=? AND timestamp>=?", (asset, since)
        ).fetchall()
        conn.close()
        if not rows:
            return 100.0
        up_count = sum(1 for (up,) in rows if up)
        return round(100.0 * up_count / len(rows), 2)

    def error_rate(self, asset: str, window_sec: int = 300) -> float:
        conn = sqlite3.connect(DB_PATH)
        since = time.time() - window_sec
        rows = conn.execute(
            "SELECT status_code FROM health_samples WHERE asset=? AND timestamp>=?", (asset, since)
        ).fetchall()
        conn.close()
        if not rows:
            return 0.0
        errors = sum(1 for (code,) in rows if code is None or code >= 500)
        return round(100.0 * errors / len(rows), 2)

    def history(self, asset: str, window_sec: int = HISTORY_WINDOW_SEC) -> list[dict]:
        conn = sqlite3.connect(DB_PATH)
        since = time.time() - window_sec
        rows = conn.execute(
            "SELECT timestamp, up, latency_ms, status_code FROM health_samples "
            "WHERE asset=? AND timestamp>=? ORDER BY timestamp ASC",
            (asset, since),
        ).fetchall()
        conn.close()
        return [{"timestamp": t, "up": bool(u), "latency_ms": lat, "status_code": sc}
                for t, u, lat, sc in rows]
