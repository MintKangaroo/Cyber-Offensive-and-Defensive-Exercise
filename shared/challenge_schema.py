"""
B0 계약: 챌린지 & 시나리오 스키마
==================================
문제(challenge.yaml)와 시나리오(scenario.yaml)의 검증 모델.
콘텐츠 계층(C0~C6, C-QA)과 시나리오 엔진(B3)이 공유한다.

이 파일은 B0만 수정한다.
"""

from __future__ import annotations
from enum import Enum
from typing import Optional, Any
from pydantic import BaseModel, Field, field_validator


class Difficulty(str, Enum):
    easy = "easy"
    medium = "medium"
    hard = "hard"
    insane = "insane"


class Category(str, Enum):
    web = "web"
    forensics = "forensics"
    detection = "detection"
    ai = "ai"
    reversing = "reversing"
    network = "network"


class SafetyProfile(str, Enum):
    standard = "standard"
    hardened = "hardened"   # RCE/AI/OT류 강격리 강제


class Hint(BaseModel):
    cost: int
    text: str


class RedTask(BaseModel):
    goal: str
    flag_format: Optional[str] = None
    flag_type: str = "static"          # static|dynamic
    submit_fields: list[str] = Field(default_factory=list)  # 조사형 다필드
    hints: list[Hint] = Field(default_factory=list)


class BlueTask(BaseModel):
    goal: str
    success_criteria: str
    points_breakdown: dict[str, int] = Field(default_factory=dict)


class Scoring(BaseModel):
    red_verify: Optional[str] = None   # flag_match|field_match|event|detector_query...
    blue_verify: Any = None            # str 또는 list[str]


class Points(BaseModel):
    red: int = 0
    blue: int = 0


class Challenge(BaseModel):
    id: str
    title: str
    category: Category
    difficulty: Difficulty
    points: Points
    asset: Optional[str] = None
    mitre: list[str] = Field(default_factory=list)
    # NICE Framework(SP 800-181r1) work role id 목록. 비우면 category에서 파생(nice_framework).
    nice: list[str] = Field(default_factory=list)
    description: str = ""
    red_task: Optional[RedTask] = None
    blue_task: Optional[BlueTask] = None
    scoring: Optional[Scoring] = None
    artifacts: list[str] = Field(default_factory=list)
    safety_profile: SafetyProfile = SafetyProfile.standard

    @field_validator("id")
    @classmethod
    def id_format(cls, v: str) -> str:
        # 예: WEB-002, FOR-002, AI-002
        import re
        if not re.match(r"^[A-Z]{2,4}-\d{3}$", v):
            raise ValueError("challenge id must look like 'WEB-002'")
        return v


# ---- 시나리오(다단계 킬체인) ----
class Stage(BaseModel):
    stage: int
    name: str
    objective_event: str               # EventType 값
    match: dict[str, Any]
    points: int
    requires_stage: Optional[int] = None
    mitre: list[str] = Field(default_factory=list)
    is_final: bool = False


class ChainBonus(BaseModel):
    all_stages_in_order: int = 0
    within_sec: Optional[int] = None


class BlueObjective(BaseModel):
    name: str
    points: int
    match_alert: Optional[str] = None
    match_event: Optional[str] = None
    match: dict[str, Any] = Field(default_factory=dict)
    time_bonus: bool = False


class Noise(BaseModel):
    enabled: bool = False
    normal_traffic_eps: int = 0


class Scenario(BaseModel):
    id: str
    name: str
    description: str = ""
    target_asset: str
    difficulty: Difficulty = Difficulty.medium
    time_limit_sec: int = 1800
    initial_vuln_state: dict[str, str] = Field(default_factory=dict)  # {vuln_id: vulnerable|patched}
    stages: list[Stage] = Field(default_factory=list)
    chain_bonus: Optional[ChainBonus] = None
    blue_objectives: list[BlueObjective] = Field(default_factory=list)
    noise: Optional[Noise] = None
