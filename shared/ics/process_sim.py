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


@dataclass(frozen=True)
class ProcessState:
    actual_rpm: float
    coolant_temp: float


def _clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def step(state: ProcessState, cmd_rpm: float, coolant_flow: float,
         dt: float, p: ProcessParams) -> ProcessState:
    """dt 초 진행. cmd_rpm=명령 RPM, coolant_flow=냉각수 유량."""
    # RPM: 명령값으로 slew 제한 접근
    max_delta = p.slew_rpm_per_s * dt
    rpm = state.actual_rpm + _clamp(cmd_rpm - state.actual_rpm, -max_delta, max_delta)

    # 온도: 발열(정격 초과분) - 냉각(유량), 주변온도 하한
    heat = p.k_heat * max(0.0, rpm - p.nominal_rpm)
    cooling = p.k_cool * max(0.0, coolant_flow)
    temp = state.coolant_temp + (heat - cooling) * dt
    temp = max(p.ambient_temp, temp)
    return ProcessState(actual_rpm=rpm, coolant_temp=temp)
