from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


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
    database_url: str = ""
    database_connect_timeout_seconds: int = 5
    database_statement_timeout_ms: int = 10_000
    database_application_name: str = "cyber-range-attack-defense"
    max_database_clock_skew_seconds: float = 5.0
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
    koth_default_lease_rounds: int = 2
    koth_default_points_per_round: int = 3
    stealth_alert_delay_rounds: int = 2
    stealth_detection_window_rounds: int = 2
    stealth_attacker_undetected_points: int = 2
    stealth_defender_detection_points: int = 2
    max_stealth_reports_per_minute: int = 30
    max_flag_submissions_per_minute: int = 120
    max_patch_submissions_per_hour: int = 10
    patch_validation_timeout_seconds: int = 180
    patch_deploy_timeout_seconds: int = 60
    patch_max_image_size_mb: int = 1024
    game_runtime: str = "docker_compose"
    allowed_registry: str = "registry.local:5000"
    runtime_registry: str = "localhost:5000"
    kubernetes_image_registry: str = "registry.local:5000"
    kubernetes_context: str = ""
    kubernetes_kubeconfig: Path | None = None
    kubernetes_kubectl: str = "kubectl"
    kubernetes_namespace_prefix: str = "ad"
    kubernetes_field_manager: str = "cyber-range-ad-runtime"
    kubernetes_rollout_timeout_seconds: int = 180
    kubernetes_pod_security_version: str = "latest"
    kubernetes_storage_class: str = ""
    kubernetes_storage_size: str = "1Gi"
    kubernetes_pvc_access_mode: str = "ReadWriteMany"
    kubernetes_manage_namespaces: bool = True
    kubernetes_cpu_request: str = "100m"
    kubernetes_cpu_limit: str = "500m"
    kubernetes_memory_request: str = "128Mi"
    kubernetes_memory_limit: str = "512Mi"
    flag_secret: str = "attack-defense-dev-flag-secret-change-me"
    flag_hash_secret: str = "attack-defense-dev-hash-secret-change-me"
    management_token: str = "attack-defense-dev-management-token"
    engine_poll_seconds: float = 1.0
    engine_lock_seconds: int = 20
    allow_insecure_dev_auth: bool = False
    auto_engine: bool = True
    pcap_storage_dir: Path | None = None
    pcap_release_delay_seconds: int = 900
    pcap_max_upload_mb: int = 32
    pcap_max_packets: int = 250_000
    pcap_max_downloads_per_minute: int = 10
    pcap_max_future_skew_seconds: int = 300
    pcap_anonymization_secret: str = "attack-defense-dev-pcap-anonymize-change-me"
    pcap_watermark_secret: str = "attack-defense-dev-pcap-watermark-change-me"

    @classmethod
    def from_env(cls) -> "AttackDefenseSettings":
        data_dir = Path(os.environ.get("ATTACK_DEFENSE_DATA_DIR", os.environ.get("DATA_DIR", "/tmp")))
        return cls(
            enabled=_bool("ATTACK_DEFENSE_ENABLED", True),
            database_path=Path(os.environ.get("ATTACK_DEFENSE_DB_PATH", str(data_dir / "attack_defense.db"))),
            database_url=os.environ.get("ATTACK_DEFENSE_DATABASE_URL", "").strip(),
            database_connect_timeout_seconds=_int(
                "ATTACK_DEFENSE_DB_CONNECT_TIMEOUT_SECONDS", 5, 1
            ),
            database_statement_timeout_ms=_int(
                "ATTACK_DEFENSE_DB_STATEMENT_TIMEOUT_MS", 10_000, 100
            ),
            database_application_name=os.environ.get(
                "ATTACK_DEFENSE_DB_APPLICATION_NAME",
                "cyber-range-attack-defense",
            ).strip(),
            max_database_clock_skew_seconds=float(os.environ.get(
                "ATTACK_DEFENSE_MAX_DB_CLOCK_SKEW_SECONDS", "5"
            )),
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
            koth_default_lease_rounds=_int("KOTH_DEFAULT_LEASE_ROUNDS", 2, 1),
            koth_default_points_per_round=_int(
                "KOTH_DEFAULT_POINTS_PER_ROUND", 3, 0
            ),
            stealth_alert_delay_rounds=_int(
                "STEALTH_ALERT_DELAY_ROUNDS", 2, 1
            ),
            stealth_detection_window_rounds=_int(
                "STEALTH_DETECTION_WINDOW_ROUNDS", 2, 1
            ),
            stealth_attacker_undetected_points=_int(
                "STEALTH_ATTACKER_UNDETECTED_POINTS", 2, 0
            ),
            stealth_defender_detection_points=_int(
                "STEALTH_DEFENDER_DETECTION_POINTS", 2, 0
            ),
            max_stealth_reports_per_minute=_int(
                "MAX_STEALTH_REPORTS_PER_MINUTE", 30, 1
            ),
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
            kubernetes_image_registry=os.environ.get(
                "KUBERNETES_IMAGE_REGISTRY", "registry.local:5000"
            ).strip(),
            kubernetes_context=os.environ.get("KUBERNETES_CONTEXT", "").strip(),
            kubernetes_kubeconfig=(
                Path(value).expanduser()
                if (value := os.environ.get("KUBERNETES_KUBECONFIG", "").strip())
                else None
            ),
            kubernetes_kubectl=os.environ.get("KUBERNETES_KUBECTL", "kubectl").strip(),
            kubernetes_namespace_prefix=os.environ.get(
                "KUBERNETES_NAMESPACE_PREFIX", "ad"
            ).strip(),
            kubernetes_field_manager=os.environ.get(
                "KUBERNETES_FIELD_MANAGER", "cyber-range-ad-runtime"
            ).strip(),
            kubernetes_rollout_timeout_seconds=_int(
                "KUBERNETES_ROLLOUT_TIMEOUT_SECONDS", 180, 10
            ),
            kubernetes_pod_security_version=os.environ.get(
                "KUBERNETES_POD_SECURITY_VERSION", "latest"
            ).strip(),
            kubernetes_storage_class=os.environ.get(
                "KUBERNETES_STORAGE_CLASS", ""
            ).strip(),
            kubernetes_storage_size=os.environ.get(
                "KUBERNETES_STORAGE_SIZE", "1Gi"
            ).strip(),
            kubernetes_pvc_access_mode=os.environ.get(
                "KUBERNETES_PVC_ACCESS_MODE", "ReadWriteMany"
            ).strip(),
            kubernetes_manage_namespaces=_bool("KUBERNETES_MANAGE_NAMESPACES", True),
            kubernetes_cpu_request=os.environ.get(
                "KUBERNETES_CPU_REQUEST", "100m"
            ).strip(),
            kubernetes_cpu_limit=os.environ.get(
                "KUBERNETES_CPU_LIMIT", "500m"
            ).strip(),
            kubernetes_memory_request=os.environ.get(
                "KUBERNETES_MEMORY_REQUEST", "128Mi"
            ).strip(),
            kubernetes_memory_limit=os.environ.get(
                "KUBERNETES_MEMORY_LIMIT", "512Mi"
            ).strip(),
            flag_secret=os.environ.get("ATTACK_DEFENSE_FLAG_SECRET", cls.flag_secret).strip(),
            flag_hash_secret=os.environ.get("ATTACK_DEFENSE_FLAG_HASH_SECRET", cls.flag_hash_secret).strip(),
            management_token=os.environ.get("ATTACK_DEFENSE_MANAGEMENT_TOKEN", cls.management_token).strip(),
            engine_poll_seconds=float(os.environ.get("ATTACK_DEFENSE_ENGINE_POLL_SECONDS", "1")),
            engine_lock_seconds=_int("ATTACK_DEFENSE_ENGINE_LOCK_SECONDS", 20, 5),
            allow_insecure_dev_auth=_bool("ATTACK_DEFENSE_ALLOW_INSECURE_DEV_AUTH", False),
            auto_engine=_bool("ATTACK_DEFENSE_AUTO_ENGINE", True),
            pcap_storage_dir=Path(os.environ.get(
                "PCAP_STORAGE_DIR", str(data_dir / "captures")
            )),
            pcap_release_delay_seconds=_int("PCAP_RELEASE_DELAY_SECONDS", 900, 0),
            pcap_max_upload_mb=_int("PCAP_MAX_UPLOAD_MB", 32, 1),
            pcap_max_packets=_int("PCAP_MAX_PACKETS", 250_000, 1),
            pcap_max_downloads_per_minute=_int(
                "PCAP_MAX_DOWNLOADS_PER_MINUTE", 10, 1
            ),
            pcap_max_future_skew_seconds=_int(
                "PCAP_MAX_FUTURE_SKEW_SECONDS", 300, 0
            ),
            pcap_anonymization_secret=os.environ.get(
                "PCAP_ANONYMIZATION_SECRET", cls.pcap_anonymization_secret
            ).strip(),
            pcap_watermark_secret=os.environ.get(
                "PCAP_WATERMARK_SECRET", cls.pcap_watermark_secret
            ).strip(),
        )

    def validate(self) -> None:
        if not 0 < self.availability_quorum <= 1:
            raise ValueError("AVAILABILITY_QUORUM must be in (0, 1]")
        if self.koth_default_lease_rounds > 20:
            raise ValueError("KOTH_DEFAULT_LEASE_ROUNDS must not exceed 20")
        if self.koth_default_points_per_round > 100_000:
            raise ValueError("KOTH_DEFAULT_POINTS_PER_ROUND is too large")
        if self.stealth_alert_delay_rounds > 20:
            raise ValueError("STEALTH_ALERT_DELAY_ROUNDS must not exceed 20")
        if not 1 <= self.stealth_detection_window_rounds <= self.stealth_alert_delay_rounds:
            raise ValueError(
                "STEALTH_DETECTION_WINDOW_ROUNDS must not exceed alert delay"
            )
        if (
            self.stealth_attacker_undetected_points > 100_000
            or self.stealth_defender_detection_points > 100_000
        ):
            raise ValueError("Stealth score defaults are too large")
        if self.database_url:
            parsed = urlsplit(self.database_url)
            if (
                parsed.scheme not in {"postgres", "postgresql"}
                or not parsed.hostname or parsed.fragment
            ):
                raise ValueError(
                    "ATTACK_DEFENSE_DATABASE_URL must be a PostgreSQL URL"
                )
        if not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}",
            self.database_application_name,
        ):
            raise ValueError("invalid database application name")
        if self.max_database_clock_skew_seconds <= 0:
            raise ValueError("database clock skew threshold must be positive")
        if not self.flag_secret or not self.flag_hash_secret:
            raise ValueError("Attack/Defense flag secrets must not be empty")
        if self.flag_secret == self.flag_hash_secret:
            raise ValueError("Flag issue and lookup secrets must be different")
        if self.game_runtime not in {"docker_compose", "kubernetes"}:
            raise ValueError("GAME_RUNTIME must be docker_compose or kubernetes")
        if not self.kubernetes_image_registry or not self.kubernetes_kubectl:
            raise ValueError("Kubernetes image registry and kubectl must not be empty")
        if not self.pcap_anonymization_secret or not self.pcap_watermark_secret:
            raise ValueError("PCAP privacy secrets must not be empty")
        if self.pcap_anonymization_secret == self.pcap_watermark_secret:
            raise ValueError("PCAP anonymization and watermark secrets must be different")
