"""
NOC API
=========
NOC 대시보드가 소비하는 API. Health Poller를 백그라운드로 돌리며,
복구 조건 충족 시 Recovery Watcher 콜백(asset_recovered 이벤트 발행)을 트리거한다.

실행: uvicorn services.noc_monitor.api.main:app --port 8070
"""
from __future__ import annotations
import asyncio
import time
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState

import sys
sys.path.append(str(Path(__file__).parent.parent.parent.parent))
from services.noc_monitor.health_poller import HealthPoller  # noqa: E402
from services.core.recovery_watcher import RecoveryWatcher  # noqa: E402

TWIN_HEALTH_URLS = {
    "ground_station": "http://ground_station:8001/health",
    "power_plant": "http://power_plant:8002/health",
    "defense_network": "http://defense_network:8003/health",
}

app = FastAPI(title="NOC Monitoring API")
poller = HealthPoller(TWIN_HEALTH_URLS)
# Recovery Watcher는 같은 poller 인스턴스를 공유해야 한다(콜백이 인메모리이기 때문).
# asset_compromised 이벤트는 Event Collector의 WS를 구독하는 별도 태스크가
# recovery_watcher.record_compromise(asset, vuln_id, team_id)를 호출해 채워준다.
recovery_watcher = RecoveryWatcher(poller)
_ws_clients: set[WebSocket] = set()


async def _broadcast_health_change(asset: str) -> None:
    """대시보드용 알림(복구 후보 감지 시 시각적 피드백). 실제 점수 판정은 RecoveryWatcher가 별도로 수행."""
    await _broadcast({"type": "health_recovery_candidate", "asset": asset, "timestamp": time.time()})


poller.on_recovery_condition_met(_broadcast_health_change)


EVENT_COLLECTOR_WS_URL = "ws://event_collector:8010/ws"


async def _subscribe_compromise_events() -> None:
    """Event Collector의 실시간 스트림을 구독해 asset_compromised 이벤트를
    Recovery Watcher에 전달한다(복구 판정의 전제조건 1번을 채움)."""
    import websockets
    import json
    while True:
        try:
            async with websockets.connect(EVENT_COLLECTOR_WS_URL) as ws:
                async for message in ws:
                    event = json.loads(message)
                    if event.get("event_type") == "asset_compromised":
                        recovery_watcher.record_compromise(
                            asset=event.get("target_asset"),
                            vuln_id=event.get("vuln_id", "unknown"),
                            team_id=event.get("team_id", "default"),
                            scenario_id=event.get("scenario_id", "default"),
                        )
        except Exception:
            await asyncio.sleep(5)  # 재연결 백오프


@app.on_event("startup")
async def startup():
    asyncio.create_task(poller.poll_forever())
    asyncio.create_task(_subscribe_compromise_events())


@app.get("/health")
def health():
    return {"status": "ok", "service": "noc_monitor"}


@app.get("/noc/status")
def status():
    result = poller.current_status()
    for asset in result:
        result[asset]["uptime_pct_1h"] = poller.uptime_pct(asset, window_sec=3600)
        result[asset]["error_rate_5m"] = poller.error_rate(asset, window_sec=300)
    return {"assets": result, "timestamp": time.time()}


@app.get("/noc/history")
def history(asset: str, window_sec: int = 3600):
    if asset not in TWIN_HEALTH_URLS:
        return {"error": f"unknown asset '{asset}'"}
    return {"asset": asset, "samples": poller.history(asset, window_sec)}


async def _broadcast(payload: dict) -> None:
    dead = set()
    for ws in _ws_clients:
        try:
            if ws.client_state == WebSocketState.CONNECTED:
                await ws.send_json(payload)
        except Exception:
            dead.add(ws)
    _ws_clients.difference_update(dead)


@app.websocket("/noc/ws")
async def noc_stream(websocket: WebSocket):
    await websocket.accept()
    _ws_clients.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        _ws_clients.discard(websocket)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8070)
