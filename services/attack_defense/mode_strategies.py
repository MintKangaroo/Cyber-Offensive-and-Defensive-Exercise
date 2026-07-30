from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class AttackPolicy(Protocol):
    def team_to_team_enabled(self) -> bool: ...


class CheckerPolicy(Protocol):
    def round_checker_enabled(self) -> bool: ...


class InjectPolicy(Protocol):
    def operator_injects_enabled(self) -> bool: ...
    def injects_required(self) -> bool: ...


class ServiceDeploymentPolicy(Protocol):
    def symmetric_services_required(self) -> bool: ...


class ScoreVisibilityPolicy(Protocol):
    def public_delay_rounds(self, configured_delay: int) -> int: ...


class MatchModeStrategy(Protocol):
    mode: str
    score_categories: tuple[str, ...]
    attack_policy: AttackPolicy
    checker_policy: CheckerPolicy
    inject_policy: InjectPolicy
    deployment_policy: ServiceDeploymentPolicy
    visibility_policy: ScoreVisibilityPolicy

    def flag_defense_category(self) -> str: ...


@dataclass(frozen=True)
class BooleanAttackPolicy:
    enabled: bool

    def team_to_team_enabled(self) -> bool:
        return self.enabled


@dataclass(frozen=True)
class BooleanCheckerPolicy:
    enabled: bool

    def round_checker_enabled(self) -> bool:
        return self.enabled


@dataclass(frozen=True)
class OptionalInjectPolicy:
    enabled: bool
    required: bool = False

    def operator_injects_enabled(self) -> bool:
        return self.enabled

    def injects_required(self) -> bool:
        return self.required


@dataclass(frozen=True)
class SymmetricDeploymentPolicy:
    required: bool

    def symmetric_services_required(self) -> bool:
        return self.required


@dataclass(frozen=True)
class ConfiguredVisibilityPolicy:
    def public_delay_rounds(self, configured_delay: int) -> int:
        return max(0, configured_delay)


@dataclass(frozen=True)
class Strategy:
    mode: str
    score_categories: tuple[str, ...]
    attack_policy: AttackPolicy
    checker_policy: CheckerPolicy
    inject_policy: InjectPolicy
    deployment_policy: ServiceDeploymentPolicy
    visibility_policy: ScoreVisibilityPolicy
    defense_category: str

    def flag_defense_category(self) -> str:
        return self.defense_category


STRATEGIES: dict[str, MatchModeStrategy] = {
    # Exercise remains executed by the legacy scenario/range/inject/scoring
    # services. This descriptor prevents A/D behavior from being applied.
    "exercise": Strategy(
        "exercise",
        ("detection", "containment", "recovery", "incident_response", "mission_inject", "penalty"),
        BooleanAttackPolicy(False), BooleanCheckerPolicy(False),
        OptionalInjectPolicy(True, False), SymmetricDeploymentPolicy(False),
        ConfiguredVisibilityPolicy(), "defense",
    ),
    "attack_defense": Strategy(
        "attack_defense",
        ("attack", "defense", "availability", "penalty", "adjustment"),
        BooleanAttackPolicy(True), BooleanCheckerPolicy(True),
        OptionalInjectPolicy(False, False), SymmetricDeploymentPolicy(True),
        ConfiguredVisibilityPolicy(), "defense",
    ),
    "hybrid_live_fire": Strategy(
        "hybrid_live_fire",
        (
            "attack", "flag_defense", "availability", "detection", "containment",
            "recovery", "incident_response", "mission_inject", "penalty", "adjustment",
        ),
        BooleanAttackPolicy(True), BooleanCheckerPolicy(True),
        OptionalInjectPolicy(True, False), SymmetricDeploymentPolicy(True),
        ConfiguredVisibilityPolicy(), "flag_defense",
    ),
}


def strategy_for(mode: str) -> MatchModeStrategy:
    try:
        return STRATEGIES[mode]
    except KeyError:
        raise ValueError(f"unsupported match mode: {mode}")


def default_score_weights(mode: str) -> dict[str, float]:
    return {category: 1.0 for category in strategy_for(mode).score_categories}
