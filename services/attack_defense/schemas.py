from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator


class MatchCreateRequest(BaseModel):
    id: str | None = Field(default=None, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    name: str = Field(min_length=1, max_length=120)
    mode: str = Field(
        default="attack_defense",
        pattern=r"^(attack_defense|hybrid_live_fire)$",
    )
    round_duration_seconds: int | None = Field(default=None, ge=5, le=3600)
    active_flag_window: int | None = Field(default=None, ge=1, le=20)
    config: dict[str, Any] = Field(default_factory=dict)


class TeamCreateRequest(BaseModel):
    id: str | None = Field(default=None, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    slug: str = Field(min_length=2, max_length=40, pattern=r"^[a-z0-9][a-z0-9-]+$")
    name: str = Field(min_length=1, max_length=80)


class ServiceCreateRequest(BaseModel):
    id: str | None = Field(default=None, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    slug: str = Field(min_length=2, max_length=50, pattern=r"^[a-z0-9][a-z0-9-]+$")
    name: str = Field(min_length=1, max_length=80)
    base_image: str = Field(min_length=3, max_length=300)
    base_image_digest: str | None = Field(default=None, max_length=80)
    internal_port: int = Field(ge=1, le=65535)
    checker_type: str = Field(pattern=r"^(vulnerable_notes|file_vault)$")
    config: dict[str, Any] = Field(default_factory=dict)


class ReasonRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=500)


class FlagSubmitRequest(BaseModel):
    flag: str = Field(min_length=1, max_length=128)


class PatchSubmitRequest(BaseModel):
    image_reference: str = Field(min_length=5, max_length=300)


class AdjustmentRequest(BaseModel):
    team_id: str = Field(min_length=1, max_length=64)
    service_id: str | None = Field(default=None, max_length=64)
    round_id: str | None = Field(default=None, max_length=64)
    delta: int = Field(ge=-100000, le=100000)
    reason: str = Field(min_length=3, max_length=500)


class RuntimeCompleteRequest(BaseModel):
    success: bool
    result: dict[str, Any] = Field(default_factory=dict)

    @field_validator("result")
    @classmethod
    def limit_result(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(str(value)) > 8000:
            raise ValueError("runtime result too large")
        return value


class ExtendRoundRequest(BaseModel):
    seconds: int = Field(ge=1, le=3600)


class CaptureFlow(BaseModel):
    ts: float = 0.0
    src_ip: str = Field(default="", max_length=64)
    dst_ip: str = Field(default="", max_length=64)
    payload: str = Field(default="", max_length=16384)


class CaptureSanitizeRequest(BaseModel):
    recipient_team_id: str = Field(min_length=1, max_length=64)
    capture_ts: float
    flows: list[CaptureFlow] = Field(default_factory=list, max_length=2000)
    active_flags: list[str] = Field(default_factory=list, max_length=5000)
    team_ips: dict[str, str] = Field(default_factory=dict)
    reason: str = Field(min_length=3, max_length=500)


class ServiceEnableRequest(BaseModel):
    enabled: bool
    reason: str = Field(min_length=3, max_length=500)


class AnnouncementRequest(BaseModel):
    message: str = Field(min_length=1, max_length=1000)
    severity: str = Field(default="info", pattern=r"^(info|warning|critical)$")
    reason: str = Field(min_length=3, max_length=500)


class ScoreEventRequest(BaseModel):
    event_id: str = Field(min_length=8, max_length=160)
    team_id: str = Field(min_length=1, max_length=64)
    score_type: str = Field(
        pattern=(
            r"^(attack|defense|flag_defense|availability|detection|containment|"
            r"recovery|incident_response|mission_inject|penalty|adjustment)$"
        )
    )
    delta: int = Field(ge=-100000, le=100000)
    reason: str = Field(min_length=3, max_length=500)
    round_id: str | None = Field(default=None, max_length=64)
    service_id: str | None = Field(default=None, max_length=64)
    evidence: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
