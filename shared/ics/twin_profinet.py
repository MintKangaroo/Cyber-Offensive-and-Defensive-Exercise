"""
ICS 트윈 Profinet DCP 배선 헬퍼(audit §5)
==========================================
트윈을 "진짜 Profinet DCP 를 말하는 IO 디바이스"로 만든다. 실 발견 도구(예: profinet
스캐너, nmap profinet 스크립트류)가 DCP Identify/Get 프레임을 던지면, 트윈이 규격대로
응답하면서 **디바이스 발견(recon)** 을 SIEM 로그 + red 이벤트로 남긴다.

배선 내용:
  - ProfinetDevice + 실 DCP-over-TCP 서버(기본 34964, `serve()`)
  - 요청 콜백: DCP 요청 1건마다 SIEM access 로그(`protocol: "profinet"`, Blue 탐지) +
    red_attack_started 이벤트(phase=initial_access, DCP Identify=디바이스 발견)
  - `PROFINET_ENABLED` env 로 게이트(기본 on), `PROFINET_PORT` 로 포트 변경

전송 정직성은 shared/ics/profinet.py 도크스트링 참조(DCP 프레임은 규격대로, 전송만 TCP).
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass

from shared.event_client import emit_event
from shared.event_schema import Event, EventType, RedPhase
from shared.siem_access_log import get_siem_logger
from shared.ics.profinet import (ProfinetDevice, serve as _pn_serve,
                                 SERVICE_IDENTIFY, SERVICE_GET, SERVICE_SET)

_SERVICE_NAME = {SERVICE_IDENTIFY: "Identify", SERVICE_GET: "Get", SERVICE_SET: "Set"}


@dataclass
class ProfinetIcsConfig:
    asset: str
    vuln_id: str                       # 발견-적합 섹터 vuln(예: FAC-001)
    device: ProfinetDevice
    red_event: EventType = EventType.red_attack_started
    red_phase: RedPhase = RedPhase.initial_access


class _ProfinetTwin:
    def __init__(self, cfg: ProfinetIcsConfig):
        self.cfg = cfg
        self.server = None
        self.siem = get_siem_logger(cfg.asset)

    def _on_request(self, service_id, service_type, xid, body):
        c = self.cfg
        svc = _SERVICE_NAME.get(service_id, f"svc{service_id}")
        # SIEM access 로그(Blue 탐지 규칙이 raw.protocol="profinet" 매칭)
        try:
            self.siem.info(json.dumps({
                "ts": time.time(), "asset": c.asset, "method": "PROFINET-DCP",
                "endpoint": f"/profinet/dcp/{svc.lower()}",
                "status": 200, "vuln_id": c.vuln_id, "team_id": "default",
                "trace_id": Event.session_trace_id("profinet", c.asset),
                "protocol": "profinet", "dcp_service": svc,
                "station_name": c.device.station_name}))
        except Exception:
            pass
        # red 이벤트: DCP 요청 = 디바이스 발견/정찰
        try:
            emit_event(
                event_id=Event.make_id("profinet", c.asset, c.vuln_id, svc, str(time.time())),
                event_type=c.red_event, actor="red", target_asset=c.asset,
                vuln_id=c.vuln_id, phase=c.red_phase, team_id="default",
                trace_id=Event.session_trace_id("profinet", c.asset),
                metadata={"protocol": "profinet", "dcp_service": svc, "xid": xid,
                          "station_name": c.device.station_name,
                          "note": "Profinet DCP device discovery/recon"})
        except Exception:
            pass

    async def _start(self):
        if os.environ.get("PROFINET_ENABLED", "1") != "1":
            return
        try:
            self.server = await _pn_serve(
                self.cfg.device, "0.0.0.0",
                int(os.environ.get("PROFINET_PORT", "34964")),
                on_request=self._on_request)
        except OSError:
            pass


def attach_profinet(app, asset: str, vuln_id: str, device: ProfinetDevice,
                    red_event: EventType = EventType.red_attack_started,
                    red_phase: RedPhase = RedPhase.initial_access) -> _ProfinetTwin:
    """FastAPI 앱에 실 Profinet DCP 배선을 붙인다. 반환된 트윈으로 server/device 접근."""
    twin = _ProfinetTwin(ProfinetIcsConfig(asset=asset, vuln_id=vuln_id, device=device,
                                            red_event=red_event, red_phase=red_phase))

    @app.on_event("startup")
    async def _startup():
        await twin._start()

    return twin
