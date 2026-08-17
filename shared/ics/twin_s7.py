"""
트윈 ↔ 실 S7comm 결합 (§5 실 프로토콜 확장)
=============================================
`attach_s7(app, ...)` 는 FastAPI 트윈 앱에 실제 S7comm/TCP 서버(포트 102)를 붙인다.
S7 클라이언트/스캐너가 COTP 연결 + Setup + Read Var(DB 워드)로 PLC 메모리를 읽으면, 그 자체가
미인증 S7 접근(정찰)이므로 이벤트를 발행하고 SIEM에 남긴다(Blue 탐지). twin_opcua와 동일.
"""
from __future__ import annotations

import asyncio
import json
import os
import time

from shared.ics import s7comm
from shared.siem_access_log import get_siem_logger


def attach_s7(app, *, asset: str, vuln_id: str,
              db_init: list[int] | None = None,
              port_env: str = "S7_PORT", default_port: int = 102) -> None:
    siem = get_siem_logger(asset)
    outstation = s7comm.S7Outstation(db=list(db_init) if db_init else [0] * 64)
    server_ref: dict = {}

    def _on_read(db_num: int, start: int, count: int):
        try:
            siem.info(json.dumps({
                "ts": time.time(), "asset": asset, "protocol": "s7comm",
                "endpoint": f"/s7/read/DB{db_num}", "method": "S7",
                "status": 200, "vuln_id": vuln_id,
                "note": f"unauthenticated S7 Read Var DB{db_num} start={start} words={count}"}))
        except Exception:
            pass
        try:
            from shared.event_client import emit_event
            from shared.event_schema import Event, EventType, RedPhase
            emit_event(
                event_id=Event.make_id("s7", asset, vuln_id, str(time.time())),
                event_type=EventType.red_attack_started, actor="red", target_asset=asset,
                vuln_id=vuln_id, phase=RedPhase.initial_access, team_id="default",
                trace_id=Event.session_trace_id("s7", asset),
                metadata={"protocol": "s7comm", "operation": "read_var", "db": db_num,
                          "ics_technique": "T0888", "severity": "medium"})
        except Exception:
            pass

    outstation.on_read = _on_read

    @app.on_event("startup")
    async def _start_s7():
        if os.environ.get("S7_ENABLED", "1") != "1":
            return
        port = int(os.environ.get(port_env, str(default_port)))
        try:
            server_ref["srv"] = await s7comm.serve(outstation, host="0.0.0.0", port=port)
        except OSError:
            pass  # 102 바인딩 실패(권한 등) 시 HTTP 트윈은 계속 동작
