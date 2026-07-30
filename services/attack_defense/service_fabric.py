from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


SAFE_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")


@dataclass(frozen=True)
class RuntimeResult:
    success: bool
    runtime_id: str
    endpoint: str | None = None
    image_digest: str | None = None
    error_code: str | None = None


class ServiceRuntime(Protocol):
    def deploy(self, instance: dict) -> RuntimeResult: ...
    def stop(self, instance: dict) -> RuntimeResult: ...
    def restart(self, instance: dict) -> RuntimeResult: ...
    def inspect(self, instance: dict) -> RuntimeResult: ...
    def replace_image(self, instance: dict, image_digest: str) -> RuntimeResult: ...
    def get_endpoint(self, instance: dict) -> str: ...


class DeclaredComposeRuntime:
    """Runtime used by the API container.

    It operates only on instances already declared by Compose.  It never opens
    Docker's root-equivalent socket.  Image replacements are delegated to the
    host runner through `runtime_jobs`.
    """

    def deploy(self, instance: dict) -> RuntimeResult:
        return RuntimeResult(
            bool(instance.get("endpoint")), instance.get("runtime_id") or instance["id"],
            instance.get("endpoint"), instance.get("image_digest"),
            None if instance.get("endpoint") else "endpoint_not_declared",
        )

    def stop(self, instance: dict) -> RuntimeResult:
        return RuntimeResult(False, instance.get("runtime_id") or instance["id"], error_code="host_runner_required")

    def restart(self, instance: dict) -> RuntimeResult:
        return RuntimeResult(False, instance.get("runtime_id") or instance["id"], error_code="host_runner_required")

    def inspect(self, instance: dict) -> RuntimeResult:
        return self.deploy(instance)

    def replace_image(self, instance: dict, image_digest: str) -> RuntimeResult:
        return RuntimeResult(False, instance.get("runtime_id") or instance["id"], image_digest=image_digest,
                             error_code="host_runner_required")

    def get_endpoint(self, instance: dict) -> str:
        return str(instance.get("endpoint") or "")


class DockerComposeRuntime:
    """Trusted host-side Compose adapter.

    This class is intentionally not instantiated by the API service.  The CLI
    runner passes an explicit compose file/project and executes one validated
    service at a time.
    """

    def __init__(self, compose_file: Path, project: str, timeout_seconds: int = 60):
        if not SAFE_NAME.fullmatch(project):
            raise ValueError("unsafe compose project name")
        self.compose_file = Path(compose_file).resolve()
        if not self.compose_file.is_file():
            raise ValueError("compose file not found")
        self.project = project
        self.timeout_seconds = timeout_seconds

    def _run(self, service: str, *args: str, env: dict[str, str] | None = None) -> RuntimeResult:
        if not SAFE_NAME.fullmatch(service):
            raise ValueError("unsafe compose service name")
        command = [
            "docker", "compose", "-p", self.project, "-f", str(self.compose_file),
            *args, service,
        ]
        try:
            completed = subprocess.run(
                command, capture_output=True, text=True, timeout=self.timeout_seconds,
                env={**os.environ, **(env or {})}, check=False,
            )
        except subprocess.TimeoutExpired:
            return RuntimeResult(False, service, error_code="runtime_timeout")
        return RuntimeResult(
            completed.returncode == 0, service,
            error_code=None if completed.returncode == 0 else "runtime_command_failed",
        )

    def deploy(self, instance: dict) -> RuntimeResult:
        return self._run(
            instance["runtime_id"], "up", "-d", "--no-deps", "--wait",
            "--wait-timeout", str(self.timeout_seconds),
        )

    def stop(self, instance: dict) -> RuntimeResult:
        return self._run(instance["runtime_id"], "stop")

    def restart(self, instance: dict) -> RuntimeResult:
        return self._run(instance["runtime_id"], "restart")

    def inspect(self, instance: dict) -> RuntimeResult:
        return self._run(instance["runtime_id"], "ps")

    def replace_image(self, instance: dict, image_digest: str) -> RuntimeResult:
        env_key = f"AD_IMAGE_{instance['runtime_id'].upper().replace('-', '_')}"
        result = self._run(
            instance["runtime_id"], "up", "-d", "--no-deps", "--pull", "always",
            "--wait", "--wait-timeout", str(self.timeout_seconds),
            env={env_key: image_digest},
        )
        return RuntimeResult(
            result.success, result.runtime_id, instance.get("endpoint"), image_digest,
            result.error_code,
        )

    def get_endpoint(self, instance: dict) -> str:
        return str(instance.get("endpoint") or "")
