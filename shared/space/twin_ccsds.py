"""
위성 트윈 CCSDS 배선 헬퍼 — 실 TT&C 를 말하는 지상국/위성
=========================================================
ground_station 에서 검증한 "실 CCSDS Space Packet + 텔레메트리 노출 + 미인가 텔레커맨드
탐지(MITRE T0855) + Blue 대응" 배선을 `attach_ccsds(app, ...)` 한 줄로 패키징한다.
twin_modbus.attach_modbus 와 동일한 형태:

  - SpacecraftState + 실 CCSDS/TCP 서버(기본 1234)
  - on_tc 콜백: 모든 텔레커맨드는 인증 없이 수신됨(우주 링크 미인증 취약점) →
      SIEM access 로그(JSON, protocol="ccsds") + red_attack_started 이벤트
  - 자세제어 안전(SIS) 해제 커맨드 → asset_compromised(위성 자세 상실 임팩트)
  - CCSDS_ENABLED 환경변수로 on/off (기본 활성)
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Optional

from shared.event_client import emit_event
from shared.event_schema import Event, EventType, RedPhase
from shared.siem_access_log import get_siem_logger
from shared.space.ccsds import (
    SpacecraftState, serve as _ccsds_serve,
    COMMAND_NAMES, TC, CMD_DISABLE_ATTITUDE_SAFETY, DEFAULT_PORT,
)


class _CcsdsTwin:
    def __init__(self, app, asset: str, vuln_id: str, state: Optional[SpacecraftState] = None,
                 red_phase: RedPhase = RedPhase.lateral_movement):
        self.asset = asset
        self.vuln_id = vuln_id
        self.red_phase = red_phase
        self.state = state if state is not None else SpacecraftState()
        self.server = None
        self.siem = get_siem_logger(asset)

    def _on_tc(self, packet: bytes, hdr: dict, data: bytes):
        """수신된 모든 텔레커맨드 = 미인증 우주 링크 커맨드 → Blue 탐지 소스로 흘린다."""
        if hdr.get("type") != TC:
            return
        command = data[0] if data else None
        cmd_name = COMMAND_NAMES.get(command, f"0x{command:02X}" if command is not None else "?")
        apid = hdr.get("apid")
        trace = Event.session_trace_id("ccsds", self.asset)

        # SIEM access 로그(twin 파서가 raw 로 보존 → proto_ccsds 규칙이 raw.protocol 매칭)
        try:
            self.siem.info(json.dumps({
                "ts": time.time(), "asset": self.asset, "method": "CCSDS",
                "endpoint": f"/ccsds/tc/apid/{apid}/cmd/{cmd_name}",
                "status": 200, "vuln_id": self.vuln_id, "team_id": "default",
                "trace_id": trace,
                "protocol": "ccsds", "apid": apid, "command": cmd_name,
                "seq_count": hdr.get("seq_count"),
            }))
        except Exception:
            pass

        # 미인가 텔레커맨드 이벤트(T0855 Unauthorized Command Message)
        try:
            emit_event(
                event_id=Event.make_id("ccsds", self.asset, self.vuln_id, cmd_name, str(time.time())),
                event_type=EventType.red_attack_started, actor="red", target_asset=self.asset,
                vuln_id=self.vuln_id, phase=self.red_phase, team_id="default", trace_id=trace,
                metadata={"protocol": "ccsds", "apid": apid, "command": cmd_name,
                          "seq_count": hdr.get("seq_count")})
        except Exception:
            pass

        # 자세제어 안전 해제 → 위성 자세 상실(즉시 임팩트)
        if command == CMD_DISABLE_ATTITUDE_SAFETY:
            try:
                emit_event(
                    event_id=Event.make_id("ccsds", self.asset, "SAFETY", "ATTITUDE", str(time.time())),
                    event_type=EventType.asset_compromised, actor="red", target_asset=self.asset,
                    vuln_id=self.vuln_id, phase=self.red_phase, team_id="default", trace_id=trace,
                    metadata={"protocol": "ccsds", "safety_impact": "attitude_safety_disabled",
                              "impact": "spacecraft_attitude_loss", "command": cmd_name,
                              "severity": "critical"})
            except Exception:
                pass

    async def _start(self):
        if os.environ.get("CCSDS_ENABLED", "1") != "1":
            return
        try:
            port = int(os.environ.get("CCSDS_PORT", str(DEFAULT_PORT)))
            self.server = await _ccsds_serve(self.state, "0.0.0.0", port, on_tc=self._on_tc)
        except OSError:
            pass   # 포트 점유/권한 문제로 트윈이 죽지 않게


def attach_ccsds(app, asset: str, vuln_id: str, state: Optional[SpacecraftState] = None,
                 red_phase: RedPhase = RedPhase.lateral_movement) -> _CcsdsTwin:
    """FastAPI 앱에 실 CCSDS TT&C 배선을 붙인다. 반환된 트윈 객체로 state 접근 가능."""
    twin = _CcsdsTwin(app, asset, vuln_id, state=state, red_phase=red_phase)

    @app.on_event("startup")
    async def _startup():
        await twin._start()

    return twin
