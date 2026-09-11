"""
Rubric scoring — pure helper shared by instructor-review workflows.
A rubric is a flat list of ``{criterion, max}``; grading is manual (an instructor
awards points per criterion). Each awarded score is clamped to ``[0, max]`` and
missing criteria score 0. Never raises on bad input; returns ``(total, max_total)``.
"""
from __future__ import annotations

from typing import Any


def rubric_total(rubric: list[dict], scores: dict) -> tuple[int, int]:
    total = 0
    max_total = 0
    for item in rubric:
        if not isinstance(item, dict):
            continue
        criterion = item.get("criterion")
        try:
            cap = int(item.get("max", 0) or 0)
        except (TypeError, ValueError):
            cap = 0
        max_total += max(0, cap)
        raw = scores.get(criterion, 0) if isinstance(scores, dict) else 0
        try:
            raw = int(raw)
        except (TypeError, ValueError):
            raw = 0
        total += max(0, min(max(0, cap), raw))
    return total, max_total


def review_breakdown(rubric: list[dict], scores: dict) -> list[dict[str, Any]]:
    """항목별 상한·부여 점수 상세(프로필 표시용)."""
    out: list[dict[str, Any]] = []
    for item in rubric:
        if not isinstance(item, dict):
            continue
        criterion = item.get("criterion")
        try:
            cap = max(0, int(item.get("max", 0) or 0))
        except (TypeError, ValueError):
            cap = 0
        raw = scores.get(criterion, 0) if isinstance(scores, dict) else 0
        try:
            raw = int(raw)
        except (TypeError, ValueError):
            raw = 0
        out.append({"criterion": criterion, "max": cap, "awarded": max(0, min(cap, raw))})
    return out
