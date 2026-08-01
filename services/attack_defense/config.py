from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int, minimum: int = 0) -> int:
    return max(minimum, int(os.environ.get(name, str(default))))


@dataclass(frozen=True)
class AttackDefenseSettings:
    enabled: bool = True
    database_path: Path = Path("/tmp/attack_defense.db")
    round_duration_seconds: int = 120
    active_flag_window_rounds: int = 3
    check_interval_seconds: int = 30
    check_timeout_seconds: int = 10
    check_retry_count: int = 2
    scoreboard_delay_rounds: int = 0
    attack_score_per_flag: int = 10
    defense_score_per_flag: int = 5
    availability_score_per_round: int = 5
    availability_quorum: float = 0.6
    max_flag_submissions_per_minute: int = 120
    max_patch_submissions_per_hour: int = 10
    patch_validation_timeout_seconds: int = 180
    patch_deploy_timeout_seconds: int = 60
    patch_max_image_size_mb: int = 1024
    game_runtime: str = "docker_compose"
    allowed_registry: str = "registry.local:5000"
    runtime_registry: str = "localhost:5000"
    flag_secret: str = "attack-defense-dev-flag-secret-change-me"
    flag_hash_secret: str = "attack-defense-dev-hash-secret-change-me"
    management_token: str = "attack-defense-dev-management-token"
    engine_poll_seconds: float = 1.0
    engine_lock_seconds: int = 20
    allow_insecure_dev_auth: bool = False
    auto_engine: bool = True

    @classmethod
    def from_env(cls) -> "AttackDefenseSettings":
        data_dir = Path(os.environ.get("ATTACK_DEFENSE_DATA_DIR", os.environ.get("DATA_DIR", "/tmp")))
        return cls(
            enabled=_bool("ATTACK_DEFENSE_ENABLED", True),
            database_path=Path(os.environ.get("ATTACK_DEFENSE_DB_PATH", str(data_dir / "attack_defense.db"))),
            round_duration_seconds=_int("ROUND_DURATION_SECONDS", 120, 5),
            active_flag_window_rounds=_int("ACTIVE_FLAG_WINDOW_ROUNDS", 3, 1),
            check_interval_seconds=_int("CHECK_INTERVAL_SECONDS", 30, 1),
            check_timeout_seconds=_int("CHECK_TIMEOUT_SECONDS", 10, 1),
            check_retry_count=_int("CHECK_RETRY_COUNT", 2, 0),
            scoreboard_delay_rounds=_int("SCOREBOARD_DELAY_ROUNDS", 0, 0),
            attack_score_per_flag=_int("ATTACK_SCORE_PER_FLAG", 10, 0),
            defense_score_per_flag=_int("DEFENSE_SCORE_PER_FLAG", 5, 0),
            availability_score_per_round=_int("AVAILABILITY_SCORE_PER_ROUND", 5, 0),
            availability_quorum=float(os.environ.get("AVAILABILITY_QUORUM", "0.6")),
            max_flag_submissions_per_minute=_int("MAX_FLAG_SUBMISSIONS_PER_MINUTE", 120, 1),
            max_patch_submissions_per_hour=_int("MAX_PATCH_SUBMISSIONS_PER_HOUR", 10, 1),
            patch_validation_timeout_seconds=_int("PATCH_VALIDATION_TIMEOUT_SECONDS", 180, 1),
            patch_deploy_timeout_seconds=_int("PATCH_DEPLOY_TIMEOUT_SECONDS", 60, 1),
            patch_max_image_size_mb=_int("PATCH_MAX_IMAGE_SIZE_MB", 1024, 1),
            game_runtime=os.environ.get("GAME_RUNTIME", "docker_compose").strip(),
            allowed_registry=os.environ.get("PATCH_ALLOWED_REGISTRY", "registry.local:5000").strip(),
            runtime_registry=os.environ.get(
                "PATCH_RUNTIME_REGISTRY", "localhost:5000"
            ).strip(),
            flag_secret=os.environ.get("ATTACK_DEFENSE_FLAG_SECRET", cls.flag_secret).strip(),
            flag_hash_secret=os.environ.get("ATTACK_DEFENSE_FLAG_HASH_SECRET", cls.flag_hash_secret).strip(),
            management_token=os.environ.get("ATTACK_DEFENSE_MANAGEMENT_TOKEN", cls.management_token).strip(),
            engine_poll_seconds=float(os.environ.get("ATTACK_DEFENSE_ENGINE_POLL_SECONDS", "1")),
            engine_lock_seconds=_int("ATTACK_DEFENSE_ENGINE_LOCK_SECONDS", 20, 5),
            allow_insecure_dev_auth=_bool("ATTACK_DEFENSE_ALLOW_INSECURE_DEV_AUTH", False),
            auto_engine=_bool("ATTACK_DEFENSE_AUTO_ENGINE", True),
        )

    def validate(self) -> None:
        if not 0 < self.availability_quorum <= 1:
            raise ValueError("AVAILABILITY_QUORUM must be in (0, 1]")
        if not self.flag_secret or not self.flag_hash_secret:
            raise ValueError("Attack/Defense flag secrets must not be empty")
        if self.flag_secret == self.flag_hash_secret:
            raise ValueError("Flag issue and lookup secrets must be different")
