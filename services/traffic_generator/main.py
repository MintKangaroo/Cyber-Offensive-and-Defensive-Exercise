"""
Background Traffic Generator 서비스 (감사 §3 G-11: 네트워크 계층 배경 트래픽)
============================================================================
탐지 훈련의 전제인 '배경 소음'을 **실제 트윈을 거쳐** 생성한다. 기존
`services/siem/detection/noise_generator.py`(siem_api 내부에서 합성 로그 직접 주입)와
달리, 이 서비스는 트윈망에 소속돼 트윈의 양성 엔드포인트로 실 HTTP를 흘린다 → 트윈이
진짜 access 로그를 남김 → 공격과 동일한 SIEM 파이프라인 통과.

- 기본 OFF(`BACKGROUND_TRAFFIC_ENABLED=false`). 켜면 startup에 드라이버 루프 기동.
- `GET /health` · `GET /stats`(read 게이트) · `POST /control`(instructor: start/stop/eps).
- 호스트 미노출(트윈망 내부 전용). mem_limit로 자원 상한(감사 2.2).
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

sys.path.append(str(Path(__file__).resolve().parent.parent.parent))
from shared.rbac import require_role, require_read  # noqa: E402
from shared.lifespan import on_startup  # noqa: E402
# 상대 import: 이 모듈은 uvicorn이 `services.traffic_generator.main`으로 로드하므로
# 패키지 컨텍스트가 성립한다. driver도 `.profile`을 상대 import하므로 통일한다
# (bare import는 driver의 상대 import와 충돌하고, 표준 `profile` 모듈을 셰도잉한다).
from .driver import TrafficDriver  # noqa: E402
from .profile import TrafficProfile  # noqa: E402

ENABLED = os.environ.get("BACKGROUND_TRAFFIC_ENABLED", "false").lower() == "true"
BASE_EPS = float(os.environ.get("BACKGROUND_TRAFFIC_EPS", "1.0"))
# 자산 스코프(선택): 훈련에서 가동 중인 섹터만 겨냥하도록 콤마구분 화이트리스트.
# 미설정이면 전 트윈(기본). 안 뜬 트윈에 헛발질(=error 카운트)하는 걸 막는다.
_assets_env = os.environ.get("BACKGROUND_TRAFFIC_ASSETS", "").strip()
ASSETS = [a.strip() for a in _assets_env.split(",") if a.strip()] or None

app = FastAPI(title="Background Traffic Generator (TRAINING ONLY)")
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1|(\d{1,3}\.){3}\d{1,3}|[\w-]+\.ts\.net)(:\d+)?",
    allow_methods=["*"], allow_headers=["*"],
)

_profile = TrafficProfile(base_eps=BASE_EPS, **({"assets": ASSETS} if ASSETS else {}))
_driver = TrafficDriver(_profile)
_task: asyncio.Task | None = None


def _start() -> None:
    global _task
    if _task is not None and not _task.done():
        return
    _driver.stop()  # 이전 루프가 있으면 정리 신호(새 task가 소유권 가짐)
    _task = asyncio.create_task(_driver.run_forever())


def _stop() -> None:
    _driver.stop()


@on_startup(app)
async def _startup():
    if ENABLED:
        _start()


@app.get("/health")
def health():
    return {"status": "ok", "service": "traffic_generator", "running": _driver.running}


@app.get("/stats")
def stats(authorization: str = Header(default="")):
    require_read(authorization)
    return {
        "enabled_default": ENABLED,
        "running": _driver.running,
        "base_eps": _profile.base_eps,
        "assets": _profile.enabled_assets(),
        "stats": _driver.stats.as_dict(),
    }


class ControlRequest(BaseModel):
    action: str            # "start" | "stop"
    eps: float | None = None  # start 시 base_eps 조정(선택)


@app.post("/control")
def control(req: ControlRequest, authorization: str = Header(default="")):
    require_role(authorization, {"instructor"})
    if req.action == "start":
        if req.eps is not None:
            if req.eps <= 0:
                raise HTTPException(400, "eps must be > 0")
            _profile.base_eps = req.eps
        _start()
        return {"running": True, "base_eps": _profile.base_eps}
    if req.action == "stop":
        _stop()
        return {"running": False}
    raise HTTPException(400, f"unknown action: {req.action}")
