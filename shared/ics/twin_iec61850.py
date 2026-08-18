"""
트윈 ↔ 실 IEC 61850 MMS 결합 (§5 실 프로토콜 확장)
====================================================
`attach_iec61850(app, ...)` 는 FastAPI 트윈 앱에 실제 IEC 61850 MMS/TCP 서버(포트 102)를 붙인다.
MMS 클라이언트/스캐너가 COTP 연결 + Initiate + Read 로 변전소 IED 측정값(모선전압·선로전류·
차단기상태)을 읽으면, 그 자체가 미인증 IEC 61850 접근(정찰)이므로 이벤트를 발행하고 SIEM 에
남긴다(Blue 탐지). twin_s7 / twin_opcua 와 동일 구조.
"""
from __future__ import annotations

import asyncio
import json
import os
import time

from shared.ics import iec61850
from shared.siem_access_log import get_siem_logger


def attach_iec61850(app, *, asset: str, vuln_id: str,
                    ied: "iec61850.IED | None" = None,
                    port_env: str = "IEC61850_PORT", default_port: int = 102) -> None:
    siem = get_siem_logger(asset)
    device = ied or iec61850.IED.substation_default()
    server_ref: dict = {}

    def _log_and_emit(operation: str, note: str):
        try:
            siem.info(json.dumps({
                "ts": time.time(), "asset": asset, "protocol": "iec61850",
                "endpoint": f"/mms/{operation}", "method": "MMS",
                "status": 200, "vuln_id": vuln_id, "note": note}))
        except Exception:
            pass
        try:
            from shared.event_client import emit_event
            from shared.event_schema import Event, EventType, RedPhase
            emit_event(
                event_id=Event.make_id("iec61850", asset, vuln_id, operation, str(time.time())),
                event_type=EventType.red_attack_started, actor="red", target_asset=asset,
                vuln_id=vuln_id, phase=RedPhase.initial_access, team_id="default",
                trace_id=Event.session_trace_id("iec61850", asset),
                metadata={"protocol": "iec61850", "operation": operation,
                          "ics_technique": "T0888", "severity": "medium"})
        except Exception:
            pass

    device.on_initiate = lambda: _log_and_emit(
        "initiate", "unauthenticated IEC 61850 MMS Initiate (association)")
    device.on_read = lambda n: _log_and_emit(
        "read", f"unauthenticated IEC 61850 MMS Read of {n} IED variable(s)")

    @app.on_event("startup")
    async def _start_iec61850():
        if os.environ.get("IEC61850_ENABLED", "1") != "1":
            return
        port = int(os.environ.get(port_env, str(default_port)))
        try:
            server_ref["srv"] = await iec61850.serve(device, host="0.0.0.0", port=port)
        except OSError:
            pass  # 102 바인딩 실패(권한 등) 시 HTTP 트윈은 계속 동작
