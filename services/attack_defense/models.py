from __future__ import annotations

from enum import Enum


class MatchMode(str, Enum):
    exercise = "exercise"
    attack_defense = "attack_defense"
    hybrid_live_fire = "hybrid_live_fire"


class MatchStatus(str, Enum):
    draft = "draft"
    running = "running"
    paused = "paused"
    ended = "ended"
    failed = "failed"


class RoundStatus(str, Enum):
    pending = "pending"
    initializing = "initializing"
    active = "active"
    scoring = "scoring"
    finalized = "finalized"
    failed = "failed"


ROUND_TRANSITIONS: dict[str, set[str]] = {
    RoundStatus.pending: {RoundStatus.initializing, RoundStatus.failed},
    RoundStatus.initializing: {RoundStatus.active, RoundStatus.failed},
    RoundStatus.active: {RoundStatus.scoring, RoundStatus.failed},
    RoundStatus.scoring: {RoundStatus.finalized, RoundStatus.failed},
    RoundStatus.finalized: set(),
    RoundStatus.failed: {RoundStatus.initializing, RoundStatus.scoring},
}


class FlagStatus(str, Enum):
    issued = "issued"
    injected = "injected"
    compromised = "compromised"
    expired = "expired"
    revoked = "revoked"
    injection_failed = "injection_failed"


class CheckStatus(str, Enum):
    ok = "ok"
    failed = "failed"
    timeout = "timeout"
    checker_system_error = "checker_system_error"


class PatchStatus(str, Enum):
    uploaded = "uploaded"
    validating = "validating"
    rejected = "rejected"
    approved = "approved"
    deploying = "deploying"
    deployed = "deployed"
    rollback = "rollback"
    failed = "failed"


PATCH_TRANSITIONS: dict[str, set[str]] = {
    PatchStatus.uploaded: {PatchStatus.validating, PatchStatus.rejected, PatchStatus.failed},
    PatchStatus.validating: {PatchStatus.rejected, PatchStatus.approved, PatchStatus.failed},
    PatchStatus.approved: {PatchStatus.deploying, PatchStatus.failed},
    PatchStatus.deploying: {PatchStatus.deployed, PatchStatus.rollback, PatchStatus.failed},
    PatchStatus.rollback: {PatchStatus.failed, PatchStatus.deployed},
    PatchStatus.rejected: set(),
    PatchStatus.deployed: set(),
    PatchStatus.failed: {PatchStatus.validating},
}


def assert_transition(current: str, target: str, transitions: dict[str, set[str]]) -> None:
    if target not in transitions.get(current, set()):
        raise ValueError(f"invalid state transition: {current} -> {target}")
