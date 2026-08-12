from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

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
    claim_token: str = Field(
        min_length=24, max_length=96, pattern=r"^[A-Za-z0-9_-]+$"
    )
    result: dict[str, Any] = Field(default_factory=dict)

    @field_validator("result")
    @classmethod
    def limit_result(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(str(value)) > 8000:
            raise ValueError("runtime result too large")
        return value


class RuntimeInstanceResultRequest(BaseModel):
    success: bool
    runtime_id: str = Field(
        min_length=1, max_length=160, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"
    )
    endpoint: str | None = Field(default=None, max_length=300)
    management_endpoint: str | None = Field(default=None, max_length=300)
    image_digest: str | None = Field(
        default=None, pattern=r"^sha256:[0-9a-f]{64}$"
    )
    error_code: str | None = Field(
        default=None, max_length=80, pattern=r"^[a-z0-9_]+$"
    )
    reason: str = Field(min_length=3, max_length=500)

    @field_validator("endpoint", "management_endpoint")
    @classmethod
    def validate_endpoint(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parsed = urlsplit(value)
        if (
            parsed.scheme != "http" or not parsed.hostname or parsed.username
            or parsed.password or parsed.path not in {"", "/"}
            or parsed.query or parsed.fragment
        ):
            raise ValueError("invalid runtime endpoint")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("invalid runtime endpoint") from exc
        if port is None or not 1 <= port <= 65535:
            raise ValueError("runtime endpoint must include a valid port")
        return value.rstrip("/")


class ExtendRoundRequest(BaseModel):
    seconds: int = Field(ge=1, le=3600)
    reason: str = Field(min_length=3, max_length=500)


class ServiceEnableRequest(BaseModel):
    enabled: bool
    reason: str = Field(min_length=3, max_length=500)


class AnnouncementRequest(BaseModel):
    message: str = Field(min_length=1, max_length=1000)
    severity: str = Field(default="info", pattern=r"^(info|warning|critical)$")
    reason: str = Field(min_length=3, max_length=500)


class KothConfigureRequest(BaseModel):
    enabled: bool = True
    service_ids: list[str] = Field(default_factory=list, max_length=32)
    lease_rounds: int | None = Field(default=None, ge=1, le=20)
    points_per_round: int | None = Field(default=None, ge=0, le=100000)
    score_weight: float = Field(default=1.0, ge=0, le=100)
    reason: str = Field(min_length=3, max_length=500)

    @field_validator("service_ids")
    @classmethod
    def unique_service_ids(cls, value: list[str]) -> list[str]:
        if any(not item or len(item) > 64 for item in value):
            raise ValueError("invalid service ID")
        if len(set(value)) != len(value):
            raise ValueError("service IDs must be unique")
        return value


class StealthConfigureRequest(BaseModel):
    enabled: bool = True
    alert_delay_rounds: int | None = Field(default=None, ge=1, le=20)
    detection_window_rounds: int | None = Field(default=None, ge=1, le=20)
    attacker_undetected_points: int | None = Field(
        default=None, ge=0, le=100000
    )
    defender_detection_points: int | None = Field(
        default=None, ge=0, le=100000
    )
    attack_score_weight: float = Field(default=1.0, ge=0, le=100)
    detection_score_weight: float = Field(default=1.0, ge=0, le=100)
    reason: str = Field(min_length=3, max_length=500)


class StealthDetectionReportRequest(BaseModel):
    service_id: str = Field(
        min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$"
    )
    indicator_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_summary: str = Field(min_length=3, max_length=280)


class TournamentCreateRequest(BaseModel):
    id: str | None = Field(
        default=None, max_length=64, pattern=r"^[A-Za-z0-9_-]+$"
    )
    name: str = Field(min_length=1, max_length=120)
    bracket_size: int = Field(ge=2, le=16)
    match_mode: str = Field(pattern=r"^(attack_defense|hybrid_live_fire)$")
    round_duration_seconds: int | None = Field(default=None, ge=5, le=3600)
    active_flag_window: int | None = Field(default=None, ge=1, le=20)
    match_config: dict[str, Any] = Field(default_factory=dict)


class TournamentEntryCreateRequest(BaseModel):
    id: str | None = Field(
        default=None, max_length=64, pattern=r"^[A-Za-z0-9_-]+$"
    )
    slug: str = Field(
        min_length=2, max_length=40, pattern=r"^[a-z0-9][a-z0-9-]+$"
    )
    name: str = Field(min_length=1, max_length=80)
    identity_subject: str = Field(
        min_length=1, max_length=120, pattern=r"^[A-Za-z0-9@._:-]+$"
    )
    seed: int | None = Field(default=None, ge=1, le=16)


class TournamentServiceCreateRequest(ServiceCreateRequest):
    pass


class TournamentFixtureFinalizeRequest(BaseModel):
    winner_entry_id: str | None = Field(
        default=None, max_length=64, pattern=r"^[A-Za-z0-9_-]+$"
    )
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
