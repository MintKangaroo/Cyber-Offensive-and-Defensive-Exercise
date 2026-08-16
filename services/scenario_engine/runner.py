"""
Scenario Runner (B3)
======================
Event Collector의 이벤트 스트림을 구독하며:
  1. 단일 시나리오: stage를 순서대로 판정(requires_stage 강제), chain_bonus 계산
  2. 크로스오버 시나리오: phase 잠금 해제(locked_until), 증거 패키징(evidence bundle),
     phase별 objective/stage 판정, full_chain_bonus 계산

팀(team_id)별로 독립된 진행 상태(RunnerState)를 유지한다.
"""
from __future__ import annotations
import time
from dataclasses import dataclass, field
from typing import Any, Optional, Callable, Awaitable

from .loader import LoadedScenario, CrossoverScenario, CrossoverPhase
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))
from shared.event_schema import Event, EventType, Actor  # noqa: E402


# ---------------- 매칭 유틸 ----------------

def _match_event(event: dict, match: dict[str, Any]) -> bool:
    """이벤트 dict가 match 조건(부분 키 일치)을 만족하는지 확인. dot-path 지원(metadata.foo)."""
    for key, expected in match.items():
        actual = event
        for part in key.split("."):
            if isinstance(actual, dict) and part in actual:
                actual = actual[part]
            else:
                return False
        if actual != expected:
            return False
    return True


# ---------------- 단일 시나리오 진행 상태 ----------------

@dataclass
class SingleProgress:
    completed_stages: dict[int, float] = field(default_factory=dict)  # stage -> completed_at
    chain_bonus_awarded: bool = False
    started_at: float = field(default_factory=time.time)


class SingleScenarioTracker:
    """단일 시나리오(SAT-KILLCHAIN-01 등) 진행 판정."""

    def __init__(self, scenario, emit_event_fn: Callable[..., Awaitable[None]]):
        self.scenario = scenario
        self.emit = emit_event_fn
        self.progress: dict[str, SingleProgress] = {}   # team_id -> progress

    def _get(self, team_id: str) -> SingleProgress:
        return self.progress.setdefault(team_id, SingleProgress())

    async def process_event(self, event: dict) -> None:
        team_id = event.get("team_id", "default")
        p = self._get(team_id)

        for stage in self.scenario.stages:
            if stage.stage in p.completed_stages:
                continue  # 이미 완료
            if event.get("event_type") != stage.objective_event:
                continue
            if not _match_event(event, stage.match):
                continue
            # requires_stage 검증: 순서 강제
            if stage.requires_stage is not None and stage.requires_stage not in p.completed_stages:
                continue  # 순서 위반 -> 미인정(조용히 무시. 로깅은 상위에서)

            p.completed_stages[stage.stage] = time.time()
            await self.emit(
                event_id=Event.make_id(team_id, self.scenario.id, "stage", str(stage.stage)),
                event_type=EventType.stage_completed,
                actor="red", target_asset=self.scenario.target_asset,
                team_id=team_id, scenario_id=self.scenario.id,
                metadata={"stage": stage.stage, "name": stage.name, "points": stage.points},
            )

            if stage.is_final:
                await self._check_chain_bonus(team_id, p)

    async def _check_chain_bonus(self, team_id: str, p: SingleProgress) -> None:
        if not self.scenario.chain_bonus or p.chain_bonus_awarded:
            return
        cb = self.scenario.chain_bonus
        all_stage_nums = {s.stage for s in self.scenario.stages}
        if not all_stage_nums.issubset(p.completed_stages.keys()):
            return
        # 순서대로(오름차순 시각) 완료됐는지 확인
        ordered = sorted(p.completed_stages.items(), key=lambda kv: kv[0])
        times = [t for _, t in ordered]
        in_order_time = all(times[i] <= times[i + 1] for i in range(len(times) - 1))
        within_time = True
        if cb.within_sec:
            within_time = (max(times) - min(times)) <= cb.within_sec
        if in_order_time and within_time and cb.all_stages_in_order:
            p.chain_bonus_awarded = True
            await self.emit(
                event_id=Event.make_id(team_id, self.scenario.id, "chain_bonus"),
                event_type=EventType.red_objective_success,
                actor="red", target_asset=self.scenario.target_asset,
                team_id=team_id, scenario_id=self.scenario.id,
                metadata={"chain_bonus": cb.all_stages_in_order},
            )


# ---------------- 크로스오버 시나리오 진행 상태 ----------------

@dataclass
class PhaseProgress:
    unlocked: bool = False
    completed: bool = False
    completed_stages: dict[int, float] = field(default_factory=dict)
    submitted_objectives: dict[str, bool] = field(default_factory=dict)  # name -> ok
    evidence_bundle: list[dict] = field(default_factory=list)


@dataclass
class CrossoverProgress:
    phases: dict[str, PhaseProgress] = field(default_factory=dict)
    started_at: float = field(default_factory=time.time)


class CrossoverScenarioTracker:
    """크로스오버 시나리오(XOVER-*) 진행 판정 + phase 잠금 해제 + 증거 패키징."""

    def __init__(self, scenario: CrossoverScenario, emit_event_fn: Callable[..., Awaitable[None]]):
        self.scenario = scenario
        self.emit = emit_event_fn
        self.order = scenario.phase_order()
        self.progress: dict[str, CrossoverProgress] = {}

        # phase_order()의 첫 phase는 기본 잠금해제(locked_until 없음)
        # 나머지는 locked_until 문자열로 잠김

    def _get(self, team_id: str) -> CrossoverProgress:
        cp = self.progress.setdefault(team_id, CrossoverProgress())
        if not cp.phases:
            for i, name in enumerate(self.order):
                pp = PhaseProgress()
                if i == 0:
                    pp.unlocked = True   # 첫 phase는 즉시 시작 가능
                cp.phases[name] = pp
        return cp

    def is_unlocked(self, team_id: str, phase_name: str) -> bool:
        return self._get(team_id).phases[phase_name].unlocked

    async def process_event(self, event: dict) -> None:
        team_id = event.get("team_id", "default")
        cp = self._get(team_id)

        for phase_name in self.order:
            phase = self.scenario.phases[phase_name]
            pp = cp.phases[phase_name]
            if pp.completed or not pp.unlocked:
                continue

            # 증거 수집: emits_evidence phase는 진행 중 모든 관련 이벤트를 번들에 축적
            if phase.emits_evidence:
                pp.evidence_bundle.append(event)

            await self._evaluate_phase_stages(team_id, phase_name, phase, pp, event)

        await self._propagate_unlocks(team_id, cp)

    async def _evaluate_phase_stages(self, team_id, phase_name, phase: CrossoverPhase,
                                     pp: PhaseProgress, event: dict) -> None:
        for stage in phase.stages:
            if stage.stage in pp.completed_stages:
                continue
            if event.get("event_type") != stage.objective_event:
                continue
            if not _match_event(event, stage.match):
                continue
            if stage.requires_stage is not None and stage.requires_stage not in pp.completed_stages:
                continue

            pp.completed_stages[stage.stage] = time.time()
            await self.emit(
                event_id=Event.make_id(team_id, self.scenario.id, phase_name, "stage", str(stage.stage)),
                event_type=EventType.stage_completed,
                actor=phase.actor, target_asset=self.scenario.target_asset,
                team_id=team_id, scenario_id=self.scenario.id,
                metadata={"phase": phase_name, "stage": stage.stage, "name": stage.name, "points": stage.points},
            )
            if stage.is_final:
                pp.completed = True
                await self._on_phase_completed(team_id, phase_name, phase)

    async def submit_objective(self, team_id: str, phase_name: str, objective_name: str,
                               submitted_value: str) -> bool:
        """조사형(포렌식 등) phase의 필드 제출 채점. 외부(API)에서 호출.

        감사 4.9: 정답은 caller가 넘기지 않고 objective.answer(스키마 필드)에서 서버측으로
        조회한다(정답 노출·조작 방지). objective_name은 objective의 name 또는 submit 키 둘 다 허용.
        answer가 None인 목표는 자동 채점 불가(제출만 기록, 교관 수동 채점)."""
        cp = self._get(team_id)
        pp = cp.phases[phase_name]
        if not pp.unlocked:
            return False
        phase = self.scenario.phases[phase_name]
        obj = next((o for o in phase.objectives
                    if o.name == objective_name or o.submit == objective_name), None)
        if obj is None:
            return False
        key = obj.name
        ok = (obj.answer is not None
              and submitted_value.strip().lower() == obj.answer.strip().lower())
        pp.submitted_objectives[key] = ok
        if ok:
            await self.emit(
                event_id=Event.make_id(team_id, self.scenario.id, phase_name, key),
                event_type=EventType.stage_completed,
                actor=phase.actor, target_asset=self.scenario.target_asset,
                team_id=team_id, scenario_id=self.scenario.id,
                metadata={"phase": phase_name, "objective": key, "points": obj.points},
            )
        # 모든 objective 제출 완료 시 phase 완료 처리
        if phase.objectives and len(pp.submitted_objectives) == len(phase.objectives):
            pp.completed = True
            await self._on_phase_completed(team_id, phase_name, phase)
        return ok

    async def _on_phase_completed(self, team_id: str, phase_name: str, phase: CrossoverPhase) -> None:
        cp = self._get(team_id)
        await self._propagate_unlocks(team_id, cp)
        if all(p.completed for p in cp.phases.values()):
            await self._award_full_chain_bonus(team_id)

    async def _propagate_unlocks(self, team_id: str, cp: CrossoverProgress) -> None:
        """locked_until: 'phase_1_web.completed' 형태를 파싱해 잠금 해제."""
        for phase_name, phase in self.scenario.phases.items():
            pp = cp.phases[phase_name]
            if pp.unlocked or not phase.locked_until:
                continue
            dep_phase, _, dep_attr = phase.locked_until.partition(".")
            if dep_phase in cp.phases and dep_attr == "completed" and cp.phases[dep_phase].completed:
                pp.unlocked = True

    def get_evidence_bundle(self, team_id: str, phase_name: str) -> list[dict]:
        """다음 phase(포렌식 등)가 참조할 증거 이벤트 번들."""
        return self._get(team_id).phases[phase_name].evidence_bundle

    async def _award_full_chain_bonus(self, team_id: str) -> None:
        if not self.scenario.full_chain_bonus or not self.scenario.full_chain_bonus.all_phases_completed:
            return
        await self.emit(
            event_id=Event.make_id(team_id, self.scenario.id, "full_chain_bonus"),
            event_type=EventType.red_objective_success,
            actor="system", target_asset=self.scenario.target_asset,
            team_id=team_id, scenario_id=self.scenario.id,
            metadata={"full_chain_bonus": self.scenario.full_chain_bonus.all_phases_completed},
        )

    def get_progress_summary(self, team_id: str) -> dict:
        """대시보드용 진행 요약."""
        cp = self._get(team_id)
        return {
            phase_name: {
                "unlocked": pp.unlocked,
                "completed": pp.completed,
                "stages_done": list(pp.completed_stages.keys()),
                "objectives_done": {k: v for k, v in pp.submitted_objectives.items()},
            }
            for phase_name, pp in cp.phases.items()
        }


# ---------------- 팩토리 ----------------

def make_tracker(loaded: LoadedScenario, emit_event_fn):
    if loaded.kind == "single":
        return SingleScenarioTracker(loaded.single, emit_event_fn)
    return CrossoverScenarioTracker(loaded.crossover, emit_event_fn)
