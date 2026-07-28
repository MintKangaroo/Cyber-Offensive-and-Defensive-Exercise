"""
ICS 트윈 Modbus 배선 재사용 헬퍼(P1-1)
=======================================
power_plant/water_utility 에서 검증한 "실 Modbus + 연속물리 + 안전결과 + MITRE 탐지 + Blue 방어"
배선 전체를 하나의 config 로 패키징한다. 신규 ICS 트윈은 섹터별 레지스터/물리/안전 프로파일만
채워 `attach_modbus_ics(app, cfg)` 한 줄로 진짜 Modbus 를 말하게 된다.

배선 내용(트윈당 동일):
  - 홀딩/코일 뱅크 + 실제 Modbus/TCP 서버(502)
  - 쓰기 콜백: MITRE ICS 분류 → 이벤트 metadata + SIEM access 로그(Blue 탐지) + 미인가 쓰기 이벤트
  - 물리 안전(SIS): 인터록 해제 + 한계 초과 → asset_compromised(즉시 임팩트)
  - 연속 물리 배경 루프: 명령→ACTUAL slew, 손상 누적, 인터록 정상=트립, 지속 초과 → 파국 1회 발행
  - Blue 방어: 위험 중 인터록 재무장(coil ON) → blue_block_success
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass, field

from shared.event_client import emit_event
from shared.event_schema import Event, EventType, RedPhase
from shared.siem_access_log import get_siem_logger
from shared.ics.modbus import ModbusBank, serve as _modbus_serve
from shared.ics.safety import SafetyProfile, evaluate as _safety_eval
from shared.ics.anomaly import IcsBaseline, classify_write as _classify
from shared.ics.process_sim import (ProcessState, ProcessParams, step as _step,
                                    has_failed as _has_failed, in_danger as _in_danger)


@dataclass
class ModbusIcsConfig:
    asset: str
    vuln_id: str                       # 섹터 Modbus vuln(예: REF-004)
    reg_names: dict                    # holding addr -> 이름
    holding_init: list                 # 초기 홀딩 값
    coils_init: list                   # 초기 코일 값(interlock 포함)
    cmd_reg: int                       # 물리 명령 레지스터(sim 이 읽음)
    actual_reg: int                    # ACTUAL 텔레메트리 레지스터
    damage_reg: int                    # DAMAGE 텔레메트리 레지스터
    interlock_coil: int
    safety: SafetyProfile
    anomaly: IcsBaseline
    proc: ProcessParams
    impact: str                        # 파국 safety_impact 라벨
    red_event: EventType = EventType.red_attack_started
    red_phase: RedPhase = RedPhase.lateral_movement
    defense_label: str = "safety_interlock_rearmed"


class _ModbusIcsTwin:
    def __init__(self, cfg: ModbusIcsConfig):
        self.cfg = cfg
        self.bank = ModbusBank(holding=list(cfg.holding_init) + [0] * (16 - len(cfg.holding_init)),
                               coils=list(cfg.coils_init) + [False] * (16 - len(cfg.coils_init)))
        self.state = ProcessState(actual_rpm=float(cfg.holding_init[cfg.cmd_reg]), coolant_temp=0.0)
        self.bank.holding[cfg.actual_reg] = int(self.state.actual_rpm)
        self.failed = False
        self.server = None
        self.siem = get_siem_logger(cfg.asset)
        self.bank.on_write = self._on_write

    def _target(self, kind, addr):
        c = self.cfg
        if kind == "coil":
            return "SAFETY_INTERLOCK" if addr == c.interlock_coil else f"COIL{addr}"
        return c.reg_names.get(addr, f"HR{addr}")

    def _on_write(self, kind, addr, vals):
        c = self.cfg
        target = self._target(kind, addr)
        anomaly = _classify(c.anomaly, kind, addr, vals)
        md = {"protocol": "modbus", "register": target, "values": vals, "fc_kind": kind}
        if anomaly:
            md.update({"ics_technique": anomaly["technique"], "ics_severity": anomaly["severity"],
                       "ics_reason": anomaly["reason"]})
        # SIEM access 로그(Blue 탐지 규칙이 vuln_id/ics_technique 매칭)
        try:
            self.siem.info(json.dumps({
                "ts": time.time(), "asset": c.asset, "method": "MODBUS",
                "endpoint": f"/modbus/{'interlock' if kind == 'coil' else 'register'}/{target}",
                "status": 200, "vuln_id": c.vuln_id, "team_id": "default",
                "trace_id": Event.session_trace_id("modbus", c.asset),
                "ics_technique": anomaly["technique"] if anomaly else None, "register": target}))
        except Exception:
            pass
        # 미인가 쓰기 이벤트
        try:
            emit_event(event_id=Event.make_id("modbus", c.asset, c.vuln_id, target, str(time.time())),
                       event_type=c.red_event, actor="red", target_asset=c.asset,
                       vuln_id=c.vuln_id, phase=c.red_phase, team_id="default",
                       trace_id=Event.session_trace_id("modbus", c.asset), metadata=md)
        except Exception:
            pass
        # 즉시 물리 안전(인터록 해제 + 한계 초과)
        try:
            for b in _safety_eval(c.safety, self.bank.holding, self.bank.coils):
                if not b["contained"]:
                    emit_event(event_id=Event.make_id("modbus", c.asset, "SAFETY", b["register"], str(time.time())),
                               event_type=EventType.asset_compromised, actor="red", target_asset=c.asset,
                               vuln_id=c.vuln_id, phase=c.red_phase, team_id="default",
                               trace_id=Event.session_trace_id("modbus", c.asset),
                               metadata={"protocol": "modbus", "safety_impact": b["condition"],
                                         "register": b["register"], "value": b["value"],
                                         "impact": c.impact, "severity": b["severity"]})
        except Exception:
            pass
        # Blue 방어: 위험 중 인터록 재무장
        try:
            if kind == "coil" and addr == c.interlock_coil and vals and bool(vals[0]) \
                    and not self.failed and _in_danger(self.state, c.proc):
                emit_event(event_id=Event.make_id("blue", c.asset, "SIS-REARM", str(time.time())),
                           event_type=EventType.blue_block_success, actor="blue", target_asset=c.asset,
                           vuln_id=c.vuln_id, phase=c.red_phase, team_id="default",
                           trace_id=Event.session_trace_id("modbus", c.asset),
                           metadata={"protocol": "modbus", "defense": c.defense_label,
                                     "actual": int(self.state.actual_rpm), "damage": int(self.state.damage)})
        except Exception:
            pass

    async def _sim_loop(self):
        c = self.cfg
        while True:
            cmd = float(self.bank.holding[c.cmd_reg])
            interlock = bool(self.bank.coils[c.interlock_coil])
            self.state = _step(self.state, cmd, 0.0, dt=0.5, p=c.proc, interlock_engaged=interlock)
            self.bank.holding[c.actual_reg] = int(self.state.actual_rpm)
            self.bank.holding[c.damage_reg] = int(self.state.damage)
            if _has_failed(self.state, c.proc) and not self.failed:
                self.failed = True
                try:
                    emit_event(event_id=Event.make_id("physics", c.asset, "SAFETY", "FAILURE", str(time.time())),
                               event_type=EventType.asset_compromised, actor="red", target_asset=c.asset,
                               vuln_id=c.vuln_id, phase=c.red_phase, team_id="default",
                               trace_id=Event.session_trace_id("physics", c.asset),
                               metadata={"protocol": "modbus", "safety_impact": "catastrophic_failure",
                                         "impact": c.impact, "actual": int(self.state.actual_rpm),
                                         "severity": "critical"})
                except Exception:
                    pass
            elif interlock and self.state.damage == 0:
                self.failed = False
            await asyncio.sleep(0.5)

    async def _start(self):
        if os.environ.get("MODBUS_ENABLED", "1") != "1":
            return
        try:
            self.server = await _modbus_serve(self.bank, "0.0.0.0", int(os.environ.get("MODBUS_PORT", "502")))
        except OSError:
            pass
        asyncio.create_task(self._sim_loop())


def attach_modbus_ics(app, cfg: ModbusIcsConfig) -> _ModbusIcsTwin:
    """FastAPI 앱에 실 Modbus ICS 배선을 붙인다. 반환된 트윈 객체로 bank/state 접근 가능."""
    twin = _ModbusIcsTwin(cfg)

    @app.on_event("startup")
    async def _startup():
        await twin._start()

    return twin
