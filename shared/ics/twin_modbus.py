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

from pydantic import BaseModel

from shared.event_client import emit_event
from shared.lifespan import on_startup
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
        prev_damage = self.state.damage
        while True:
            cmd = float(self.bank.holding[c.cmd_reg])
            interlock = bool(self.bank.coils[c.interlock_coil])
            self.state = _step(self.state, cmd, 0.0, dt=0.5, p=c.proc, interlock_engaged=interlock)
            self.bank.holding[c.actual_reg] = int(self.state.actual_rpm)
            self.bank.holding[c.damage_reg] = int(self.state.damage)
            # 회복: 손상이 있던 자산이 확보되어 0 으로 회복 → asset_recovered(Blue 복구 크레딧)
            if prev_damage > 0 and self.state.damage == 0:
                try:
                    emit_event(event_id=Event.make_id("physics", c.asset, "RECOVERED", str(time.time())),
                               event_type=EventType.asset_recovered, actor="blue", target_asset=c.asset,
                               vuln_id=c.vuln_id, phase=c.red_phase, team_id="default",
                               trace_id=Event.session_trace_id("physics", c.asset),
                               metadata={"protocol": "modbus", "note": "asset secured and recovered"})
                except Exception:
                    pass
            prev_damage = self.state.damage
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

    def telemetry(self) -> dict:
        """라이브파이어 콘솔 게이지용 섹터 무관 텔레메트리(발전소 /api/telemetry 와 동일 규약).
        연속 물리 루프가 ACTUAL/DAMAGE 를 갱신하므로 폴링하면 게이지가 실제로 움직인다."""
        c = self.cfg
        cmd_name = c.reg_names.get(c.cmd_reg, f"HR{c.cmd_reg}")
        actual_name = c.reg_names.get(c.actual_reg, f"HR{c.actual_reg}")
        # 명명된 홀딩 레지스터 + 안전 인터록 코일을 그대로 노출(프런트가 섹터별 테이블을 렌더).
        regs = [{"addr": a, "name": n, "value": int(self.bank.holding[a])}
                for a, n in sorted(c.reg_names.items())]
        return {
            "asset": c.asset,
            "cmd": int(self.bank.holding[c.cmd_reg]),
            "cmd_name": cmd_name,
            "actual": int(self.bank.holding[c.actual_reg]),
            "actual_name": actual_name,
            "damage": int(self.bank.holding[c.damage_reg]),
            "interlock": bool(self.bank.coils[c.interlock_coil]),
            "failed": bool(self.failed),
            "redline": c.proc.redline_rpm,
            "registers": regs,
        }

    def apply_command(self, value: float) -> None:
        """HTTP 공격 핸들러가 물리 명령 레지스터(cmd_reg)에 값을 반영 → 연속 물리로 게이지가 움직인다.
        발전소의 _sync_bank_from_registers 와 같은 역할: HTTP 공격이 실제 물리에 도달하게 한다."""
        self.bank.holding[self.cfg.cmd_reg] = int(value)

    def set_interlock(self, engaged: bool) -> None:
        """HTTP 공격 핸들러가 안전 인터록(SIS)을 켜고 끈다 → 과속/과투입 보호 해제."""
        self.bank.coils[self.cfg.interlock_coil] = bool(engaged)

    def safety_override(self, override: bool) -> dict:
        """HTTP SIS 무력화 공격 — 발전소 `/api/safety/override` 와 동일 계약.
        override=True → 인터록 코일 OFF(보호 해제). 실 Modbus 코일 쓰기와 동일 경로(`_on_write`)로
        처리해 미인가 쓰기 이벤트·SIEM access 로그·즉시 안전평가가 발화하고, 이후 연속 물리 루프가
        한계 초과 지속 시 손상을 누적해 catastrophic_failure 까지 간다(비발전소 트윈도 파국 도달)."""
        engaged = not bool(override)
        self.bank.coils[self.cfg.interlock_coil] = engaged
        self._on_write("coil", self.cfg.interlock_coil, [engaged])
        return {"asset": self.cfg.asset, "safety_interlock": engaged, "sis_bypassed": not engaged}


class _SafetyOverrideReq(BaseModel):
    """SIS 무력화 바디(발전소와 동일): override=True → 인터록 해제."""
    override: bool = True


def attach_modbus_ics(app, cfg: ModbusIcsConfig) -> _ModbusIcsTwin:
    """FastAPI 앱에 실 Modbus ICS 배선을 붙인다. 반환된 트윈 객체로 bank/state 접근 가능."""
    twin = _ModbusIcsTwin(cfg)

    @on_startup(app)
    async def _startup():
        await twin._start()

    @app.get("/api/telemetry")
    def _telemetry():
        return twin.telemetry()

    @app.post("/api/safety/override")
    def _safety_override(req: _SafetyOverrideReq):
        # 발전소 /api/safety/override 와 동일: override=True → SIS 해제(인터록 OFF) → 파국 경로 개방.
        return twin.safety_override(req.override)

    return twin
