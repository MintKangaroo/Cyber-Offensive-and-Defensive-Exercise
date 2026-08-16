"""
Scenario Loader (B3)
======================
scenarios/single/*.yaml, scenarios/crossover/*.yaml 을 로드해 검증하고,
Config Service에 초기 취약점 상태를 주입한다.

단일 시나리오는 contracts.shared.challenge_schema.Scenario로 검증.
크로스오버 시나리오는 phase 구조가 달라(여러 phase, 각자 stages/objectives)
별도의 유연한 모델(CrossoverScenario)로 검증한다.
"""
from __future__ import annotations
import yaml
from pathlib import Path
from typing import Any, Optional
from pydantic import BaseModel, Field

import sys
sys.path.append(str(Path(__file__).parent.parent.parent))
from shared.challenge_schema import Scenario, Difficulty  # noqa: E402


# ---------------- 크로스오버 모델 ----------------

class CrossoverStage(BaseModel):
    stage: int
    name: str
    objective_event: str
    match: dict[str, Any]
    points: int
    requires_stage: Optional[int] = None
    mitre: list[str] = Field(default_factory=list)
    is_final: bool = False


class CrossoverObjective(BaseModel):
    """Forensics류 phase의 조사형 목표(필드 제출)."""
    name: str
    submit: str
    points: int
    # 감사 4.9: 정답 키를 주석이 아니라 스키마 필드로 보관한다(서버측 채점 근거).
    # None이면 자동 채점 불가(제출은 기록만; 교관 수동 채점 대상).
    answer: Optional[str] = None


class CrossoverBlueParallel(BaseModel):
    goal: str
    points: int


class CrossoverPhase(BaseModel):
    actor: str                                  # "red" | "blue"
    locked_until: Optional[str] = None          # "phase_1_web.completed" 형태
    linked_challenge: Optional[str] = None
    stages: list[CrossoverStage] = Field(default_factory=list)
    objectives: list[CrossoverObjective] = Field(default_factory=list)   # 조사형(포렌식 등)
    objective: Optional[str] = None             # 단일 목표 서술형(네트워크 등)
    success_criteria: Any = None
    expected_rule_shape: Optional[dict[str, Any]] = None
    points: Optional[int] = None
    is_final: bool = False
    completion_unlocks: Optional[str] = None
    blue_parallel: Optional[CrossoverBlueParallel] = None
    emits_evidence: bool = False
    evidence_source: Optional[str] = None
    scoring: Optional[str] = None


class ChainBonusSpec(BaseModel):
    all_phases_completed: Optional[int] = None
    all_stages_in_order: Optional[int] = None
    within_sec: Optional[int] = None
    description: str = ""


class NoiseSpec(BaseModel):
    enabled: bool = False
    normal_traffic_eps: int = 0


class SafetySpec(BaseModel):
    profile: str = "standard"
    notes: str = ""


class CrossoverScenario(BaseModel):
    id: str
    name: str
    description: str = ""
    target_asset: str
    difficulty: Difficulty = Difficulty.hard
    time_limit_sec: int = 3600
    category_chain: list[str] = Field(default_factory=list)
    initial_vuln_state: dict[str, str] = Field(default_factory=dict)
    phases: dict[str, CrossoverPhase]           # key: "phase_1_web" 등
    full_chain_bonus: Optional[ChainBonusSpec] = None
    scoring_summary: dict[str, int] = Field(default_factory=dict)
    noise: Optional[NoiseSpec] = None
    safety: Optional[SafetySpec] = None

    def phase_order(self) -> list[str]:
        """phase_1_web, phase_2_forensics, phase_3_detection 순으로 정렬."""
        def key(name: str) -> int:
            # "phase_1_web" -> 1
            try:
                return int(name.split("_")[1])
            except (IndexError, ValueError):
                return 999
        return sorted(self.phases.keys(), key=key)


# ---------------- 로더 ----------------

class LoadedScenario(BaseModel):
    kind: str                      # "single" | "crossover"
    single: Optional[Scenario] = None
    crossover: Optional[CrossoverScenario] = None


def load_scenario_file(path: str | Path) -> LoadedScenario:
    """단일/크로스오버 자동 판별 후 로드+검증. 다중 문서(--- 구분)는 첫 문서만 반환."""
    path = Path(path)
    with open(path) as f:
        docs = [d for d in yaml.safe_load_all(f) if d]
    if not docs:
        raise ValueError(f"empty or invalid YAML: {path}")
    return _load_doc(docs[0])


def load_scenario_file_all(path: str | Path) -> list[LoadedScenario]:
    """다중 문서 YAML(--- 로 여러 시나리오) 전체 로드."""
    path = Path(path)
    with open(path) as f:
        docs = [d for d in yaml.safe_load_all(f) if d]
    return [_load_doc(d) for d in docs]


def _load_doc(doc: dict) -> LoadedScenario:
    if "scenario" in doc:
        return LoadedScenario(kind="single", single=Scenario(**doc["scenario"]))
    if "crossover_scenario" in doc:
        raw = doc["crossover_scenario"]
        # phases_* 키를 phases 딕셔너리로 재구성
        phases = {
            k: v for k, v in raw.items()
            if k.startswith("phase_") and isinstance(v, dict)
        }
        rest = {k: v for k, v in raw.items() if not k.startswith("phase_")}
        rest["phases"] = phases
        return LoadedScenario(kind="crossover", crossover=CrossoverScenario(**rest))
    raise ValueError("YAML must contain 'scenario' or 'crossover_scenario' root key")


def load_all_scenarios(scenarios_dir: str | Path) -> dict[str, LoadedScenario]:
    """scenarios/single/**.yaml + scenarios/crossover/**.yaml 전체 로드."""
    scenarios_dir = Path(scenarios_dir)
    result: dict[str, LoadedScenario] = {}
    for sub in ["single", "crossover"]:
        for f in sorted((scenarios_dir / sub).glob("*.yaml")):
            for loaded in load_scenario_file_all(f):
                sid = loaded.single.id if loaded.kind == "single" else loaded.crossover.id
                result[sid] = loaded
    return result


async def inject_initial_state(loaded: LoadedScenario, config_client) -> None:
    """초기 취약점 상태를 Config Service에 주입 (04번 문서 5절 연동)."""
    state = (loaded.single or loaded.crossover).initial_vuln_state
    asset = (loaded.single or loaded.crossover).target_asset
    for vuln_id, status in state.items():
        patched = (status == "patched")
        await config_client.set_patch(asset, vuln_id, patched, reason="scenario_init")
