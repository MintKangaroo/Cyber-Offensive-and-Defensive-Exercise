"""
ICS Modbus 이상탐지 분류(P1-1 red→blue 루프) — 순수 로직
=========================================================
Red 가 실제 Modbus 로 공격하면(레지스터 조작·안전 인터록 해제) Blue/SIEM 이 그것을 탐지하고
MITRE ATT&CK for ICS 기법으로 분류할 수 있어야 한다. 트윈은 각 Modbus 쓰기를 이 분류기로
평가해 이벤트 metadata 에 실어 보내고, Blue 는 그 신호로 탐지 점수를 얻는다.

MITRE ICS 기법:
  - T0836 Modify Parameter        : 프로세스 값을 운전 밴드 밖으로 변경
  - T0855 Unauthorized Command    : 보호 레지스터에 무인증 명령
  - T0878 Suppression of Alarms   : 안전 인터록/알람 비활성화
분류는 가장 심각한 하나를 반환(없으면 None). 상태 없음 → 테스트 용이.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class RegBand:
    name: str
    low: float
    high: float
    protected: bool = False   # 정상 밴드라도 무인증 명령 자체가 신호


@dataclass
class IcsBaseline:
    name: str
    registers: dict[int, RegBand]
    safety_coils: set[int] = field(default_factory=set)


def _finding(technique: str, severity: str, register: str, reason: str, **extra) -> dict:
    return {"technique": technique, "severity": severity, "register": register,
            "reason": reason, "asset_kind": "ics_modbus", **extra}


def classify_write(baseline: IcsBaseline, kind: str, addr: int, values: list) -> dict | None:
    """Modbus 쓰기 1건 → 가장 심각한 이상 분류(없으면 None)."""
    if kind == "coil":
        on = bool(values[0]) if values else False
        if addr in baseline.safety_coils and not on:
            return _finding("T0878 (Suppression of Alarms/Interlock)", "critical",
                            f"COIL{addr}", "safety interlock disabled")
        return None

    reg = baseline.registers.get(addr)
    if reg is None:
        return _finding("T0836 (Modify Parameter)", "medium", f"HR{addr}",
                        "write to unmapped register")
    val = values[0] if values else 0
    # 운전 밴드 이탈 → 파라미터 변조. 이탈 폭으로 심각도.
    if val > reg.high or val < reg.low:
        span = max(reg.high - reg.low, 1)
        over = (val - reg.high) if val > reg.high else (reg.low - val)
        severity = "critical" if over > span else "high"
        return _finding("T0836 (Modify Parameter)", severity, reg.name,
                        f"value {val} outside operating band [{reg.low},{reg.high}]",
                        value=val, band=[reg.low, reg.high])
    # 밴드 안이지만 보호 레지스터면 무인증 명령 자체가 신호
    if reg.protected:
        return _finding("T0855 (Unauthorized Command Message)", "medium", reg.name,
                        "unauthenticated write to protected register", value=val)
    return None
