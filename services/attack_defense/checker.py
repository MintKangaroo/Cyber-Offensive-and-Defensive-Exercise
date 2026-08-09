from __future__ import annotations

import base64
import hashlib
import hmac
import json
import random
import secrets
import time
from dataclasses import dataclass
from typing import Callable, Protocol

import httpx

from .config import AttackDefenseSettings


def derive_management_token(master: str, instance: dict) -> str:
    """Derive a Kubernetes team/service secret without persisting plaintext.

    Compose keeps its existing shared development token. Kubernetes sets
    ``management_secret_scope`` so checker and trusted runtime independently
    derive the same namespace-local value from the configured master.
    """
    scope = str(instance.get("management_secret_scope") or "live")
    message = ":".join((
        "ad-management-v1", str(instance.get("match_id") or ""),
        str(instance.get("team_id") or ""),
        str(instance.get("service_id") or ""), scope,
    )).encode()
    value = hmac.new(master.encode(), message, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


@dataclass(frozen=True)
class SecretFlag:
    id: str
    token: str


@dataclass(frozen=True)
class InjectionResult:
    success: bool
    latency_ms: float
    error_code: str | None = None


@dataclass(frozen=True)
class VerificationResult:
    success: bool
    latency_ms: float
    error_code: str | None = None


@dataclass(frozen=True)
class CheckOutcome:
    check_type: str
    status: str
    latency_ms: float
    error_code: str | None = None
    evidence: dict | None = None


class FlagInjector(Protocol):
    def put_flag(self, instance: dict, flag: SecretFlag) -> InjectionResult: ...
    def verify_flag(self, instance: dict, flag: SecretFlag) -> VerificationResult: ...


class ServiceChecker(Protocol):
    def health_check(self, instance: dict) -> CheckOutcome: ...
    def protocol_check(self, instance: dict) -> CheckOutcome: ...
    def benign_workflow(self, instance: dict) -> CheckOutcome: ...
    def get_flag(self, instance: dict, flag: SecretFlag) -> CheckOutcome: ...


class ManagementSigner:
    def __init__(self, secret: str):
        self.secret = secret.encode()

    def headers(self, method: str, path: str, body: dict | None = None) -> dict[str, str]:
        timestamp = str(int(time.time()))
        nonce = secrets.token_hex(12)
        body_hash = hashlib.sha256(
            json.dumps(body or {}, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        message = "\n".join((method.upper(), path, timestamp, nonce, body_hash)).encode()
        signature = hmac.new(self.secret, message, hashlib.sha256).hexdigest()
        return {
            "X-Management-Timestamp": timestamp,
            "X-Management-Nonce": nonce,
            "X-Management-Signature": signature,
        }


class HttpFlagInjector:
    def __init__(self, settings: AttackDefenseSettings):
        self.settings = settings
        self.signer = ManagementSigner(settings.management_token)

    def _signer(self, instance: dict) -> ManagementSigner:
        if (
            self.settings.game_runtime == "kubernetes"
            or instance.get("runtime_kind") == "kubernetes"
        ):
            return ManagementSigner(
                derive_management_token(self.settings.management_token, instance)
            )
        return self.signer

    def put_flag(self, instance: dict, flag: SecretFlag) -> InjectionResult:
        path = "/management/flags"
        body = {"slot": flag.id, "value": flag.token}
        started = time.perf_counter()
        try:
            with httpx.Client(timeout=self.settings.check_timeout_seconds) as client:
                response = client.post(
                    f"{instance['management_endpoint']}{path}",
                    json=body, headers=self._signer(instance).headers("POST", path, body),
                )
            return InjectionResult(
                response.status_code in (200, 201),
                (time.perf_counter() - started) * 1000,
                None if response.status_code in (200, 201) else f"http_{response.status_code}",
            )
        except httpx.TimeoutException:
            return InjectionResult(False, (time.perf_counter() - started) * 1000, "timeout")
        except httpx.HTTPError:
            return InjectionResult(False, (time.perf_counter() - started) * 1000, "connection")

    def verify_flag(self, instance: dict, flag: SecretFlag) -> VerificationResult:
        path = "/management/flags/verify"
        body = {"slot": flag.id, "value": flag.token}
        started = time.perf_counter()
        try:
            with httpx.Client(timeout=self.settings.check_timeout_seconds) as client:
                response = client.post(
                    f"{instance['management_endpoint']}{path}",
                    json=body, headers=self._signer(instance).headers("POST", path, body),
                )
            payload = response.json() if response.status_code == 200 else {}
            return VerificationResult(
                response.status_code == 200 and payload.get("verified") is True,
                (time.perf_counter() - started) * 1000,
                None if payload.get("verified") is True else f"http_{response.status_code}",
            )
        except httpx.TimeoutException:
            return VerificationResult(False, (time.perf_counter() - started) * 1000, "timeout")
        except (httpx.HTTPError, ValueError):
            return VerificationResult(False, (time.perf_counter() - started) * 1000, "connection")


class HttpWorkflowChecker:
    """Functional checker for the two MVP HTTP services."""

    def __init__(self, settings: AttackDefenseSettings, injector: FlagInjector):
        self.settings = settings
        self.injector = injector

    def _request(self, check_type: str, fn: Callable[[], bool]) -> CheckOutcome:
        started = time.perf_counter()
        try:
            ok = fn()
            return CheckOutcome(
                check_type, "ok" if ok else "failed",
                (time.perf_counter() - started) * 1000,
                None if ok else "workflow_assertion",
            )
        except httpx.TimeoutException:
            return CheckOutcome(
                check_type, "timeout", (time.perf_counter() - started) * 1000, "timeout"
            )
        except httpx.HTTPError:
            return CheckOutcome(
                check_type, "failed", (time.perf_counter() - started) * 1000, "connection"
            )
        except Exception as exc:  # checker bug is not charged to the team
            return CheckOutcome(
                check_type, "checker_system_error",
                (time.perf_counter() - started) * 1000,
                f"checker_{type(exc).__name__}",
            )

    def health_check(self, instance: dict) -> CheckOutcome:
        def run() -> bool:
            with httpx.Client(timeout=self.settings.check_timeout_seconds) as client:
                return client.get(f"{instance['endpoint']}/health").status_code == 200
        return self._request("health", run)

    def protocol_check(self, instance: dict) -> CheckOutcome:
        def run() -> bool:
            with httpx.Client(timeout=self.settings.check_timeout_seconds) as client:
                r = client.get(f"{instance['endpoint']}/api/version")
                return r.status_code == 200 and r.json().get("protocol") == "ad-http-v1"
        return self._request("protocol", run)

    def benign_workflow(self, instance: dict) -> CheckOutcome:
        checker_type = instance["checker_type"]
        nonce = secrets.token_hex(8)
        username = f"checker_{nonce}"
        password = secrets.token_urlsafe(16)

        def run() -> bool:
            with httpx.Client(timeout=self.settings.check_timeout_seconds) as client:
                reg = client.post(
                    f"{instance['endpoint']}/api/register",
                    json={"username": username, "password": password},
                    headers={"X-Checker-Request": nonce},
                )
                if reg.status_code not in (200, 201):
                    return False
                login = client.post(
                    f"{instance['endpoint']}/api/login",
                    json={"username": username, "password": password},
                )
                if login.status_code != 200:
                    return False
                auth = {"Authorization": f"Bearer {login.json()['access_token']}"}
                marker = f"workflow-{secrets.token_hex(12)}"
                if checker_type == "vulnerable_notes":
                    created = client.post(
                        f"{instance['endpoint']}/api/notes", json={"content": marker}, headers=auth
                    )
                    if created.status_code != 201:
                        return False
                    got = client.get(
                        f"{instance['endpoint']}/api/notes/{created.json()['id']}", headers=auth
                    )
                    return got.status_code == 200 and got.json().get("content") == marker
                if checker_type == "file_vault":
                    path = f"{nonce}.txt"
                    uploaded = client.post(
                        f"{instance['endpoint']}/api/files",
                        json={"path": path, "content": marker}, headers=auth,
                    )
                    if uploaded.status_code != 201:
                        return False
                    got = client.get(
                        f"{instance['endpoint']}/api/files", params={"path": path}, headers=auth
                    )
                    return got.status_code == 200 and got.json().get("content") == marker
                raise RuntimeError("unknown checker type")
        return self._request("benign_workflow", run)

    def get_flag(self, instance: dict, flag: SecretFlag) -> CheckOutcome:
        result = self.injector.verify_flag(instance, flag)
        return CheckOutcome(
            "get_flag", "ok" if result.success else (
                "timeout" if result.error_code == "timeout" else "failed"
            ),
            result.latency_ms, result.error_code,
        )

    def run_all(self, instance: dict, flag: SecretFlag) -> list[CheckOutcome]:
        calls = [
            lambda: self.health_check(instance),
            lambda: self.protocol_check(instance),
            lambda: self.benign_workflow(instance),
            lambda: self.get_flag(instance, flag),
        ]
        random.SystemRandom().shuffle(calls)
        outcomes: list[CheckOutcome] = []
        for call in calls:
            outcome = call()
            attempts = 0
            while outcome.status in {"timeout", "failed"} and attempts < self.settings.check_retry_count:
                attempts += 1
                outcome = call()
            outcomes.append(outcome)
        return outcomes
