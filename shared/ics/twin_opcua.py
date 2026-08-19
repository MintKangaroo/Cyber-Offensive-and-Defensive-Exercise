"""
트윈 ↔ 실 OPC UA 전송 계층 결합 (§5 실 프로토콜 확장)
======================================================
`attach_opcua(app, ...)` 는 FastAPI 트윈 앱에 실제 OPC UA/TCP 서버(포트 4840)를 붙인다.
OPC UA 클라이언트/스캐너가 HEL→ACK→OPN 핸드셰이크로 접속하면, 그 자체가 미인증 OPC UA
접근(예: REF-001 anonymous read의 정찰 단계)이므로 이벤트를 발행하고 SIEM에 남긴다
(Blue 탐지 가능). Modbus 결합(attach_modbus_ics)과 동일한 방식.
"""
from __future__ import annotations

import asyncio
import json
import os
import time

from shared.ics import opcua
from shared.lifespan import on_startup
from shared.siem_access_log import get_siem_logger


def attach_opcua(app, *, asset: str, vuln_id: str,
                 port_env: str = "OPCUA_PORT", default_port: int = 4840,
                 endpoint_url: str | None = None) -> None:
    siem = get_siem_logger(asset)
    endpoint = endpoint_url or f"opc.tcp://{asset}:{default_port}"
    server_ref: dict = {}

    def _on_connect(peer):
        # 미인증 OPC UA 접속(핸드셰이크 완료) → 정찰/무단 접근 이벤트.
        src_ip = peer[0] if isinstance(peer, (tuple, list)) and peer else None
        try:
            siem.info(json.dumps({
                "ts": time.time(), "asset": asset, "protocol": "opcua",
                "endpoint": "/opcua/securechannel", "method": "OPCUA",
                "status": 200, "src_ip": src_ip, "vuln_id": vuln_id,
                "note": "unauthenticated OPC UA connect (HEL/OPN, security None)"}))
        except Exception:
            pass
        try:
            from shared.event_client import emit_event
            from shared.event_schema import Event, EventType, RedPhase
            emit_event(
                event_id=Event.make_id("opcua", asset, vuln_id, str(time.time())),
                event_type=EventType.red_attack_started, actor="red", target_asset=asset,
                vuln_id=vuln_id, phase=RedPhase.initial_access, team_id="default",
                trace_id=Event.session_trace_id("opcua", asset),
                metadata={"protocol": "opcua", "phase": "securechannel_open",
                          "security_policy": "None", "ics_technique": "T0846",
                          "severity": "medium", "src_ip": src_ip})
        except Exception:
            pass

    @on_startup(app)
    async def _start_opcua():
        if os.environ.get("OPCUA_ENABLED", "1") != "1":
            return
        port = int(os.environ.get(port_env, str(default_port)))
        try:
            server_ref["srv"] = await opcua.serve(
                host="0.0.0.0", port=port, endpoint_url=endpoint, on_connect=_on_connect)
        except OSError:
            pass  # 바인딩 실패 시 HTTP 트윈은 계속 동작
