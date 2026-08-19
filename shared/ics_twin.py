"""
ICS/OT 디지털 트윈 팩토리 (shared/ics_twin.py)
================================================
전력망/위성지상국/사내망 3종에 이어 정유·스마트팩토리·수도·LNG·철도·공항·데이터센터·병원 등
여러 ICS/OT 섹터 트윈을 **동일한 플랫폼 계약**(EDR 에이전트 / SIEM access log / Config 무중단 패치 /
격리·킬스위치 / 이벤트 발행)으로 선언적으로 만들 수 있게 하는 팩토리.

각 트윈 main.py는 `Vuln(...)` 목록과 핸들러만 선언하고 `make_ics_twin(...)`을 호출한다.
핸들러는 `handler(patched: bool, payload: dict, emit) -> dict` 시그니처를 가지며,
- 취약(unpatched): 필요 시 `emit(metadata)`로 red 이벤트를 발행하고 200 응답(민감/임팩트) 반환
- 패치(patched): HTTPException(401/403/400/404 등)으로 거부하거나 안전 응답 반환
Safe Probe는 이 상태코드 차이로 patched/vulnerable을 판정한다.

실제 산업장비와 연결되지 않으며 모든 값은 합성 더미다.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import sys
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

sys.path.append(str(Path(__file__).parent.parent))  # repo root
from shared.event_client import emit_event  # noqa: E402
from shared.lifespan import on_startup  # noqa: E402
from shared.event_schema import Event, EventType, RedPhase  # noqa: E402
from shared.config_client import ConfigClient  # noqa: E402
from shared.edr_agent import start_edr_agent  # noqa: E402
from shared.siem_access_log import make_siem_access_middleware  # noqa: E402

import os
# per-match 배포 시 이 트윈이 발행하는 이벤트의 파티션 키(매치별 트윈 셋 = MATCH_SCENARIO_ID=match_X).
# 미지정 시 "default"(공유 트윈 셋 모델). → per-match 이벤트/점수 격리의 마지막 조각.
MATCH_SCENARIO_ID = os.environ.get("MATCH_SCENARIO_ID", "default")


@dataclass
class Vuln:
    id: str                 # 예: "REF-001"
    path: str               # 예: "/api/opcua/read"
    method: str             # "GET" | "POST"
    summary: str
    event_type: str         # EventType 속성명(예: "red_attack_started")
    phase: str              # RedPhase 속성명(예: "initial_access")
    handler: Callable       # handler(patched: bool, payload: dict, emit) -> dict


def _flag_key(vuln_id: str) -> str:
    return "PATCH_" + vuln_id.replace("-", "_")


def make_ics_twin(asset_name: str, title: str, vulns: list[Vuln]) -> FastAPI:
    config = ConfigClient(asset=asset_name)
    route_map = {v.path: v.id for v in vulns}
    app = FastAPI(title=f"{title} (TRAINING ONLY)")

    @on_startup(app)
    async def _edr():
        start_edr_agent(asset_name=asset_name)

    @app.middleware("http")
    async def _guard(request: Request, call_next):
        if request.url.path != "/health":
            if config.is_killswitch_active():
                return JSONResponse(status_code=503, content={"detail": "training halted by instructor killswitch"})
            if config.is_quarantined():
                return JSONResponse(status_code=503, content={"detail": f"{asset_name} is quarantined by EDR console"})
        return await call_next(request)

    app.middleware("http")(make_siem_access_middleware(asset_name, route_map))

    @app.get("/health")
    def health():
        return {"status": "ok", "service": asset_name}

    def _bind(v: Vuln):
        def is_patched() -> bool:
            return config.is_patched(v.id, env_fallback_key=_flag_key(v.id))

        def emit(metadata: dict, team_id: str):
            emit_event(
                event_id=Event.make_id(team_id, asset_name, v.id, str(time.time())),
                event_type=getattr(EventType, v.event_type),
                actor="red", target_asset=asset_name, vuln_id=v.id,
                phase=getattr(RedPhase, v.phase), team_id=team_id,
                scenario_id=MATCH_SCENARIO_ID,
                trace_id=Event.session_trace_id(team_id, asset_name),
                metadata=metadata or {},
            )

        async def endpoint(request: Request):
            # 감사 3.3: per-team 배포는 TEAM_ID(서버측)를 권위값으로. 미설정(dev/공용)이면
            # 요청 헤더 폴백. 헤더만 신뢰하면 공격자가 타 팀에 귀속을 조작할 수 있다.
            team_id = os.environ.get("TEAM_ID", "").strip() or request.headers.get("x-team-id", "default")
            payload: dict = dict(request.query_params)
            if v.method.upper() == "POST":
                try:
                    body = await request.json()
                    if isinstance(body, dict):
                        payload.update(body)
                except Exception:
                    pass
            result = v.handler(is_patched(), payload, lambda md=None: emit(md or {}, team_id))
            if isinstance(result, dict):
                result.setdefault("patched", is_patched())
            return result

        return endpoint

    for v in vulns:
        app.add_api_route(v.path, _bind(v), methods=[v.method.upper()], name=v.id, summary=v.summary)

    return app


def deny(status: int, detail: str):
    """핸들러에서 패치 상태 거부를 표현하는 헬퍼."""
    raise HTTPException(status, detail)
