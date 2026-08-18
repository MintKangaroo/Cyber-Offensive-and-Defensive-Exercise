"""
ICS 트윈 HART-IP 배선 헬퍼(§5 실 프로토콜 확장)
================================================
twin_modbus/dnp3 와 동일한 계약으로, 정유 Tank Farm 트윈이 '실제' HART-IP(포트 5094)를
말하게 한다. HART 명령(read/write) 수신 시 SIEM access 로그(protocol=hart)를 흘려 Blue
탐지 규칙(ICS-HART-ACCESS-REF)이 매칭되게 하고, red_attack_started 이벤트를 발행한다.

HART 는 무인증(insecure-by-design) 이므로 필드 디바이스에 대한 임의 HART-IP 세션 개시 후
동적변수 열람(정찰)만으로도 미인가 접근이다.
"""
from __future__ import annotations

import json
import os
import time

from shared.event_client import emit_event
from shared.event_schema import Event, EventType, RedPhase
from shared.siem_access_log import get_siem_logger
from shared.ics.hart import HartField, serve as _hart_serve, HART_IP_DEFAULT_PORT


class _HartTwin:
    def __init__(self, asset: str, vuln_id: str, device: HartField,
                 red_phase: str, host: str, port: int):
        self.asset = asset
        self.vuln_id = vuln_id
        self.device = device
        self.red_phase = red_phase
        self.host = host
        self.port = port
        self.server = None
        self.siem = get_siem_logger(asset)
        self.device.on_command = self._on_command

    def _on_command(self, command_no: int, req_data: bytes) -> None:
        """HART 명령 수신 콜백 — SIEM 로그 + red 이벤트 발행(Blue 탐지 신호)."""
        endpoint = f"/hart/command/{command_no}"
        # SIEM access 로그(탐지 규칙이 raw.protocol=hart 매칭)
        try:
            self.siem.info(json.dumps({
                "ts": time.time(), "asset": self.asset, "protocol": "hart",
                "endpoint": endpoint, "method": "HART", "status": 200,
                "vuln_id": self.vuln_id, "team_id": "default",
                "trace_id": Event.session_trace_id("hart", self.asset),
                "command": command_no,
                "note": f"HART-IP command {command_no} on field device"}))
        except Exception:
            pass
        # 미인가 HART 접근 이벤트
        try:
            emit_event(
                event_id=Event.make_id("hart", self.asset, self.vuln_id,
                                       str(command_no), str(time.time())),
                event_type=EventType.red_attack_started, actor="red",
                target_asset=self.asset, vuln_id=self.vuln_id, phase=self.red_phase,
                team_id="default", trace_id=Event.session_trace_id("hart", self.asset),
                metadata={"protocol": "hart", "command": command_no,
                          "endpoint": endpoint,
                          "ics_technique": "T0861",
                          "severity": "medium"})
        except Exception:
            pass

    async def _start(self):
        if os.environ.get("HART_ENABLED", "1") != "1":
            return
        try:
            self.server = await _hart_serve(self.device, self.host, self.port)
        except OSError:
            pass


def attach_hart(app, asset: str, vuln_id: str, device_vars: dict,
                host: str = "0.0.0.0", port: int | None = None,
                red_phase: str = RedPhase.lateral_movement) -> _HartTwin:
    """FastAPI 앱에 실 HART-IP 필드 디바이스 배선을 붙인다.

    device_vars: {"pv","sv","tv","qv"} 및 선택적 단위코드("pv_unit" 등)로 동적변수 초기화.
    반환된 트윈 객체로 device(HartField) 상태를 갱신하면 실 마스터가 그 값을 읽는다.
    """
    dev = HartField()
    for key in ("pv", "sv", "tv", "qv", "pv_unit", "sv_unit", "tv_unit", "qv_unit",
                "loop_current", "polling_address"):
        if key in device_vars:
            setattr(dev, key, device_vars[key])
    resolved_port = int(os.environ.get("HART_PORT", str(port or HART_IP_DEFAULT_PORT)))
    twin = _HartTwin(asset, vuln_id, dev, red_phase, host, resolved_port)

    @app.on_event("startup")
    async def _startup():
        await twin._start()

    return twin
