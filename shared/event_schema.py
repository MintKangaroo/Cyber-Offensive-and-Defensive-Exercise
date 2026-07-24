"""
B0 계약: Live Fire 이벤트 스키마 (모든 서비스 공통)
====================================================
Event Collector / Scoring Engine / 트윈 / 시나리오 러너가 공유하는 단일 계약.
기존 구현(cyber-range/shared/event_schema.py)과 하위 호환되며, 확장 필드가 추가됨.

변경 규칙:
  - 이 파일은 B0(Architect)만 수정한다.
  - 필드 추가는 하위호환(옵셔널+기본값) 원칙. 필드 제거/의미변경은 major 버전업.
"""

from __future__ import annotations
from enum import Enum
from typing import Optional, Any
from datetime import datetime, timezone
import time
import uuid

from pydantic import BaseModel, Field

SCHEMA_VERSION = "1.1.0"


class EventType(str, Enum):
    red_attack_started = "red_attack_started"
    red_objective_success = "red_objective_success"
    blue_patch_verified = "blue_patch_verified"
    blue_detection_success = "blue_detection_success"
    blue_block_success = "blue_block_success"
    asset_compromised = "asset_compromised"
    asset_recovered = "asset_recovered"
    flag_exfiltrated = "flag_exfiltrated"
    scenario_started = "scenario_started"
    scenario_ended = "scenario_ended"
    score_updated = "score_updated"
    # v1.1 확장
    stage_completed = "stage_completed"          # 시나리오 킬체인 단계 완료
    red_stealth_bonus = "red_stealth_bonus"      # 미탐지 유지 보너스
    unmatched_detection = "unmatched_detection"  # 대응 공격 없는 탐지(치팅/오탐 보류)


class RedPhase(str, Enum):
    initial_access = "initial_access"            # +20
    privilege_escalation = "privilege_escalation"  # +30
    lateral_movement = "lateral_movement"        # +30
    data_exfiltration = "data_exfiltration"      # +50
    objective = "objective"                      # +100


class Actor(str, Enum):
    red = "red"
    blue = "blue"
    system = "system"


class Asset(str, Enum):
    ground_station = "ground_station"
    power_plant = "power_plant"
    defense_network = "defense_network"
    dmz = "dmz"


def utcnow() -> float:
    return datetime.now(timezone.utc).timestamp()


class Event(BaseModel):
    event_id: str
    event_type: EventType
    timestamp: float = Field(default_factory=utcnow)
    actor: Actor
    team_id: str = "default"
    scenario_id: str = "default"
    target_asset: str
    vuln_id: Optional[str] = None
    phase: Optional[RedPhase] = None
    # v1.1 확장: 공격↔탐지 상관, 챌린지 연동
    trace_id: Optional[str] = None          # 공격 세션 추적 ID(탐지 상관용)
    matched_event_id: Optional[str] = None  # 이 이벤트가 대응하는 원 이벤트(탐지→공격)
    challenge_id: Optional[str] = None       # 연관 챌린지(WEB-002 등)
    schema_version: str = SCHEMA_VERSION
    metadata: dict[str, Any] = Field(default_factory=dict)

    @staticmethod
    def make_id(*parts: str) -> str:
        """결정론적 event_id(중복 발행 dedup용). 동일 인자 → 동일 id."""
        return str(uuid.uuid5(uuid.NAMESPACE_URL, ":".join(parts)))

    @staticmethod
    def new_trace_id() -> str:
        """공격 세션 시작 시 1회 생성해 이후 관련 이벤트/로그에 전파."""
        return uuid.uuid4().hex[:16]

    @staticmethod
    def session_trace_id(team_id: str, asset: str, bucket_minutes: int = 30) -> str:
        """세션 상태를 따로 관리하기 부담스러운 트윈을 위한 결정론적 trace_id.
        같은 팀+자산에서 bucket_minutes(기본 30분) 내의 공격은 같은 trace_id를 공유해
        별도 세션 저장소 없이도 SIEM/탐지 쪽에서 대략적인 세션 상관이 가능하다.
        엄밀한 상관이 필요하면 new_trace_id()로 세션을 명시적으로 관리할 것."""
        bucket = int(time.time() // (bucket_minutes * 60))
        return uuid.uuid5(uuid.NAMESPACE_URL, f"{team_id}:{asset}:{bucket}").hex[:16]


# 점수표(제안서 10장) — Scoring Engine의 단일 진실원
RED_POINTS: dict[str, int] = {
    RedPhase.initial_access: 20,
    RedPhase.privilege_escalation: 30,
    RedPhase.lateral_movement: 30,
    RedPhase.data_exfiltration: 50,
    RedPhase.objective: 100,
}
BLUE_POINTS: dict[str, int] = {
    "patch_verified": 50,
    "detection_success": 20,
    "block_success": 30,
    "asset_recovered": 50,
}
