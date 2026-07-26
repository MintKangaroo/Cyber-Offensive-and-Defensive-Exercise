"""
비기술 인젝트(P1-4) 순수 로직 계약 고정.
- 마감 상태 판정(정시/지각/대기/만료)
- 루브릭 채점(항목별 상한 clamp + 합계)
- 지각 감점
위기 커뮤니케이션 훈련: 미디어/경영/규제 문의에 마감 내 대응했는지 + 응답 품질을 채점.
"""
import pytest

from services.injects.model import (
    CHANNELS, deadline_state, rubric_total, apply_late_penalty,
)


def test_channels_defined():
    assert {"media", "exec", "regulator", "legal"} <= set(CHANNELS)


def test_deadline_pending_before_due_no_response():
    assert deadline_state(deadline_at=100, now=50, response_at=None) == "pending"


def test_deadline_expired_after_due_no_response():
    assert deadline_state(deadline_at=100, now=150, response_at=None) == "expired"


def test_deadline_on_time_response_before_due():
    assert deadline_state(deadline_at=100, now=150, response_at=90) == "on_time"


def test_deadline_late_response_after_due():
    assert deadline_state(deadline_at=100, now=200, response_at=120) == "late"


def test_rubric_total_sums_clamped():
    rubric = [{"criterion": "정확성", "max": 10}, {"criterion": "적시성", "max": 5}]
    scores = {"정확성": 8, "적시성": 5}
    total, max_total = rubric_total(rubric, scores)
    assert total == 13 and max_total == 15


def test_rubric_clamps_over_and_negative():
    rubric = [{"criterion": "톤", "max": 10}]
    assert rubric_total(rubric, {"톤": 999})[0] == 10      # 상한 clamp
    assert rubric_total(rubric, {"톤": -5})[0] == 0        # 하한 clamp


def test_rubric_missing_criterion_scores_zero():
    rubric = [{"criterion": "a", "max": 10}, {"criterion": "b", "max": 10}]
    assert rubric_total(rubric, {"a": 7})[0] == 7          # b 미채점 = 0


def test_late_penalty_halves_by_default():
    assert apply_late_penalty(20, late=True) == 10
    assert apply_late_penalty(20, late=False) == 20


def test_late_penalty_custom_factor_rounds():
    assert apply_late_penalty(15, late=True, factor=0.8) == 12
