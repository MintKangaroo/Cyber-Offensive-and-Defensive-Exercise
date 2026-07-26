"""
ICS 안전 결과 판정(P1-1 심화) — 순수 로직
===========================================
실제 Modbus 쓰기가 만든 레지스터 상태가 '물리적으로 위험한가'를 판정한다. 트윈은 이 판정으로
단순 미인가 쓰기(PP-006)를 넘어 실제 안전 임팩트(asset_compromised)를 발행할 수 있다.

핵심 개념(SIS, Safety Instrumented System):
  - 안전 인터록(interlock)이 걸려 있으면 위험 상태에서 자동 트립 → '억제(contained)'.
  - 인터록이 해제(공격자가 코일 OFF)돼 있으면 트립이 안 걸려 '억제 실패' = 물리 임팩트(critical).
프로파일(레지스터별 min/max + 인터록 코일)만 주면 어느 ICS 트윈에도 재사용된다.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SafetyProfile:
    name: str
    limits: dict[int, dict]   # holding addr -> {"name":str, "max":?, "min":?}
    interlock_coil: int = 0


def evaluate(profile: SafetyProfile, holding: list[int], coils: list[bool]) -> list[dict]:
    """현재 레지스터/코일 상태 → 안전 위반 목록. 없으면 빈 리스트."""
    # 인터록: 코일 배열이 짧거나 False 면 '해제'(보수적으로 임팩트로 본다).
    idx = profile.interlock_coil
    interlock_engaged = bool(coils[idx]) if 0 <= idx < len(coils) else False

    breaches: list[dict] = []
    for addr, spec in profile.limits.items():
        if addr >= len(holding):
            continue
        val = holding[addr]
        cond = None
        if "max" in spec and val > spec["max"]:
            cond = "over_max"
        elif "min" in spec and val < spec["min"]:
            cond = "under_min"
        if cond:
            breaches.append({
                "asset": profile.name,
                "register": spec.get("name", f"HR{addr}"),
                "value": val,
                "condition": cond,
                "limit": spec.get("max") if cond == "over_max" else spec.get("min"),
                "contained": interlock_engaged,
                "severity": "high" if interlock_engaged else "critical",
            })
    return breaches
