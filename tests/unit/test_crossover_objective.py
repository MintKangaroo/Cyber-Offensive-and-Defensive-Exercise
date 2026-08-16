"""
크로스오버 조사형 목표 제출 + 정답 키 이전 (감사 4.9)
======================================================
- 정답이 objective.answer(스키마 필드)에서 서버측으로 조회돼 채점되는지(주석→필드 이전).
- submit_objective(caller가 정답 안 넘김) — 정답이면 True, 오답이면 False.
- objective를 name 또는 submit 키로 지정 가능.
"""
import asyncio
from pathlib import Path

import pytest

from services.scenario_engine.loader import load_scenario_file
from services.scenario_engine.runner import make_tracker

XOVER = Path("scenarios/crossover/XOVER-WEB-FOR-DET-01.yaml")


@pytest.fixture
def tracker():
    loaded = load_scenario_file(XOVER)
    emitted = []
    async def emit(**kw):
        emitted.append(kw)
    tr = make_tracker(loaded, emit)
    tr._emitted = emitted
    return tr


def _unlock(tr, team, phase):
    cp = tr._get(team)
    cp.phases[phase].unlocked = True


def test_answer_key_migrated_to_schema(tracker):
    # 정답이 주석이 아니라 answer 필드에 있어야 서버측 채점이 가능.
    phase = tracker.scenario.phases["phase_2_forensics"]
    by_submit = {o.submit: o for o in phase.objectives}
    assert by_submit["entry_vuln_id"].answer == "GS-005"
    assert by_submit["privesc_method"].answer == "JWT forgery"
    assert by_submit["timeline_json"].answer is None   # 자유서술 = 수동 채점


def test_submit_correct_and_wrong(tracker):
    _unlock(tracker, "team01", "phase_2_forensics")
    # submit 키로 지정 + 정답(대소문자 무관) → True, stage_completed 발행.
    ok = asyncio.run(tracker.submit_objective("team01", "phase_2_forensics", "entry_vuln_id", "gs-005"))
    assert ok is True
    assert any(e.get("metadata", {}).get("objective") == "공격자 진입점 특정" for e in tracker._emitted)
    # 오답 → False.
    bad = asyncio.run(tracker.submit_objective("team01", "phase_2_forensics", "privesc_method", "sql injection"))
    assert bad is False


def test_locked_phase_rejects(tracker):
    # phase가 잠겨 있으면(선행 phase 미완료) 제출 거부.
    res = asyncio.run(tracker.submit_objective("team01", "phase_2_forensics", "entry_vuln_id", "GS-005"))
    assert res is False
