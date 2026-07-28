"""
ICS 연속 물리 시뮬(P1-1 심화) — 순수 동역학
=============================================
레지스터를 순간값이 아니라 실제 공정처럼 시간에 따라 반응하게 한다. 공격자는 값을 '쓰면
즉시 반영'되는 게 아니라, 프로세스가 slew-rate/열역학에 따라 응답하는 것을 읽고 추론해야 한다.

- 터빈 RPM: 명령값으로 초당 slew_rpm_per_s 만큼만 접근(관성).
- 냉각수 온도: RPM 이 정격 초과분에 비례해 승온(발열), 유량에 비례해 냉각. 주변온도 하한.

step() 은 상태 없는 순수함수 → 단위 테스트 용이. 트윈이 배경 루프에서 dt 마다 호출해
읽기전용 텔레메트리 레지스터(ACTUAL_RPM/COOLANT_TEMP)를 갱신한다.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProcessParams:
    slew_rpm_per_s: float = 500.0   # RPM 최대 변화율
    nominal_rpm: float = 3000.0     # 정격(이 이상에서 발열)
    ambient_temp: float = 40.0      # 주변/하한 온도
    k_heat: float = 0.02            # 발열 계수(RPM 초과분당)
    k_cool: float = 0.5             # 냉각 계수(유량당)
    redline_rpm: float = 4500.0     # 기계적 한계(초과 시 트립/손상)
    crit_temp: float = 120.0        # 임계 온도(초과 시 손상)
    damage_rpm_rate: float = 0.01   # RPM redline 초과분당 손상률/초
    damage_temp_rate: float = 0.05  # 온도 임계 초과분당 손상률/초
    failure_threshold: float = 100.0  # 누적 손상이 이 값 도달 시 파국
    heal_rate: float = 2.0          # 인터록 재무장+안전 상태에서 손상 회복률/초(0=회복 없음)


@dataclass(frozen=True)
class ProcessState:
    actual_rpm: float
    coolant_temp: float
    damage: float = 0.0             # 누적 손상(0~failure_threshold). 인터록 해제 시에만 증가.


def _clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def step(state: ProcessState, cmd_rpm: float, coolant_flow: float,
         dt: float, p: ProcessParams, interlock_engaged: bool = True) -> ProcessState:
    """dt 초 진행. interlock_engaged=True(정상)면 redline 에서 트립(RPM 캡)·손상 없음.
    False(공격자가 SIS 무력화)면 캡 없이 지속 과속·과열이 손상으로 누적된다."""
    # RPM: 명령값으로 slew 제한 접근
    max_delta = p.slew_rpm_per_s * dt
    rpm = state.actual_rpm + _clamp(cmd_rpm - state.actual_rpm, -max_delta, max_delta)
    # SIS 트립: 인터록 정상이면 redline 초과분을 잘라낸다(자동 안전정지).
    if interlock_engaged and rpm > p.redline_rpm:
        rpm = p.redline_rpm

    # 온도: 발열(정격 초과분) - 냉각(유량), 주변온도 하한
    heat = p.k_heat * max(0.0, rpm - p.nominal_rpm)
    cooling = p.k_cool * max(0.0, coolant_flow)
    temp = max(p.ambient_temp, state.coolant_temp + (heat - cooling) * dt)

    # 손상: 인터록 해제 상태에서 redline/임계온도 초과분에 비례해 누적,
    #       인터록 재무장 + 안전(밴드 내) 상태에서는 회복(heal) — 자산 재실행 가능.
    damage = state.damage
    if not interlock_engaged:
        damage += p.damage_rpm_rate * max(0.0, rpm - p.redline_rpm) * dt
        damage += p.damage_temp_rate * max(0.0, temp - p.crit_temp) * dt
    elif rpm <= p.redline_rpm and temp <= p.crit_temp:
        damage = max(0.0, damage - p.heal_rate * dt)
    damage = min(p.failure_threshold, damage)
    return ProcessState(actual_rpm=rpm, coolant_temp=temp, damage=damage)


def has_failed(state: ProcessState, p: ProcessParams) -> bool:
    return state.damage >= p.failure_threshold


def in_danger(state: ProcessState, p: ProcessParams) -> bool:
    """공정이 위험 상태인가(redline 초과·임계온도 초과·손상 진행). 방어 액션 유효성 판정용."""
    return (state.actual_rpm > p.redline_rpm or state.coolant_temp > p.crit_temp
            or state.damage > 0)
