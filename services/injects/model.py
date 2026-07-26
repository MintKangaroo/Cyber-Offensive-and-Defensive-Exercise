"""
비기술 인젝트 순수 로직(P1-4)
==============================
마감 판정·루브릭 채점·지각 감점을 상태 없는 순수함수로 분리(테스트 용이).

인젝트 = 훈련 중 팀에게 도착하는 비기술 상황(언론 문의/경영진 요구/규제기관 통보/법무).
마감 내에 응답했는지 + 응답 품질(루브릭)을 교관이 채점한다.
"""
from __future__ import annotations

CHANNELS = ("media", "exec", "regulator", "legal", "customer", "internal")


def deadline_state(deadline_at: float, now: float, response_at: float | None) -> str:
    """마감 대비 상태.
    - 응답 있음: 마감 이내면 on_time, 초과면 late.
    - 응답 없음: 현재 마감 지났으면 expired, 아니면 pending.
    """
    if response_at is not None:
        return "on_time" if response_at <= deadline_at else "late"
    return "expired" if now > deadline_at else "pending"


def rubric_total(rubric: list[dict], scores: dict) -> tuple[int, int]:
    """루브릭 채점 합계. 항목별 [0, max] 로 clamp. 반환 (합계, 만점)."""
    total = 0
    max_total = 0
    for item in rubric:
        crit = item.get("criterion")
        mx = int(item.get("max", 0))
        max_total += mx
        raw = scores.get(crit, 0)
        try:
            raw = int(raw)
        except (TypeError, ValueError):
            raw = 0
        total += max(0, min(mx, raw))
    return total, max_total


def apply_late_penalty(total: int, late: bool, factor: float = 0.5) -> int:
    """지각 응답 감점(기본 절반). 정시면 그대로."""
    return int(round(total * factor)) if late else total
