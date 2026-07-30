from __future__ import annotations

from dataclasses import dataclass

from services.attack_defense.checker import (
    CheckOutcome,
    InjectionResult,
    SecretFlag,
    VerificationResult,
)
from services.attack_defense.patch_pipeline import ManifestInfo
from services.attack_defense.service_fabric import RuntimeResult


class FakeInjector:
    def __init__(self):
        self.values: dict[tuple[str, str], str] = {}

    def put_flag(self, instance: dict, flag: SecretFlag) -> InjectionResult:
        self.values[(instance["id"], flag.id)] = flag.token
        return InjectionResult(True, 1.0)

    def verify_flag(self, instance: dict, flag: SecretFlag) -> VerificationResult:
        return VerificationResult(
            self.values.get((instance["id"], flag.id)) == flag.token, 1.0
        )


class FakeChecker:
    def __init__(self):
        self.injector = FakeInjector()

    def run_all(self, instance: dict, flag: SecretFlag) -> list[CheckOutcome]:
        verified = self.injector.verify_flag(instance, flag).success
        return [
            CheckOutcome("health", "ok", 1),
            CheckOutcome("protocol", "ok", 1),
            CheckOutcome("benign_workflow", "ok", 1),
            CheckOutcome("get_flag", "ok" if verified else "failed", 1),
        ]


class FakeRuntime:
    def deploy(self, instance: dict) -> RuntimeResult:
        return RuntimeResult(True, instance["runtime_id"], instance.get("endpoint"), instance.get("image_digest"))

    def stop(self, instance: dict) -> RuntimeResult:
        return RuntimeResult(True, instance["runtime_id"])

    def restart(self, instance: dict) -> RuntimeResult:
        return RuntimeResult(True, instance["runtime_id"])

    def inspect(self, instance: dict) -> RuntimeResult:
        return self.deploy(instance)

    def replace_image(self, instance: dict, image_digest: str) -> RuntimeResult:
        return RuntimeResult(True, instance["runtime_id"], instance.get("endpoint"), image_digest)

    def get_endpoint(self, instance: dict) -> str:
        return instance.get("endpoint", "")


@dataclass
class FakeInspector:
    digest: str = "sha256:" + ("a" * 64)
    size_bytes: int = 10_000
    labels: dict[str, str] | None = None
    environment: tuple[str, ...] = ()

    def inspect(self, _: str) -> ManifestInfo:
        return ManifestInfo(
            self.digest, self.size_bytes, self.labels or {}, self.environment
        )
