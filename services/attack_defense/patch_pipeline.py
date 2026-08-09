from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx

from .checker import HttpWorkflowChecker, SecretFlag
from .config import AttackDefenseSettings
from .db import Database
from .evidence import AuditContext, EvidenceRecorder
from .models import PATCH_TRANSITIONS, PatchStatus, assert_transition
from .repositories import AttackDefenseRepository
from .utils import canonical_json, stable_id

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
PATH_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]{1,180}$")


def _runtime_endpoint(value: object, *, kubernetes: bool) -> str | None:
    """Accept only non-credentialed HTTP endpoints returned by a trusted runner."""
    if not value:
        return None
    endpoint = str(value)
    parsed = urlsplit(endpoint)
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
    if kubernetes and not parsed.hostname.endswith(".svc"):
        raise ValueError("Kubernetes runtime endpoint must use cluster DNS")
    return endpoint.rstrip("/")


@dataclass(frozen=True)
class ManifestInfo:
    digest: str
    size_bytes: int
    labels: dict[str, str] = field(default_factory=dict)
    environment: tuple[str, ...] = ()


class RegistryInspector(Protocol):
    def inspect(self, image_reference: str) -> ManifestInfo: ...


def parse_image_reference(reference: str) -> tuple[str, str, str]:
    if "@" in reference:
        before, digest = reference.rsplit("@", 1)
        tag = digest
    else:
        slash = reference.rfind("/")
        colon = reference.rfind(":")
        if colon <= slash:
            raise ValueError("image tag or digest is required")
        before, tag = reference[:colon], reference[colon + 1:]
    if "/" not in before:
        raise ValueError("registry and repository namespace are required")
    registry, repository = before.split("/", 1)
    if not registry or not PATH_RE.fullmatch(repository):
        raise ValueError("invalid image reference")
    return registry, repository, tag


class HttpRegistryInspector:
    """Minimal OCI/Docker Registry v2 manifest inspector."""

    def __init__(self, timeout_seconds: int):
        self.timeout_seconds = timeout_seconds

    def inspect(self, image_reference: str) -> ManifestInfo:
        registry, repository, tag = parse_image_reference(image_reference)
        scheme = "http" if registry.startswith(("localhost", "127.0.0.1", "registry.local")) else "https"
        manifest_url = f"{scheme}://{registry}/v2/{repository}/manifests/{tag}"
        accept = (
            "application/vnd.oci.image.manifest.v1+json,"
            "application/vnd.docker.distribution.manifest.v2+json,"
            "application/vnd.oci.image.index.v1+json,"
            "application/vnd.docker.distribution.manifest.list.v2+json"
        )
        with httpx.Client(timeout=self.timeout_seconds) as client:
            response = client.get(manifest_url, headers={"Accept": accept})
            response.raise_for_status()
            root_bytes = response.content
            root = response.json()
            digest = response.headers.get("Docker-Content-Digest") or (
                "sha256:" + hashlib.sha256(root_bytes).hexdigest()
            )
            manifest = root
            if root.get("manifests"):
                candidates = [
                    item for item in root["manifests"]
                    if (item.get("platform") or {}).get("os") == "linux"
                    and (item.get("platform") or {}).get("architecture") in {
                        "amd64", "x86_64",
                    }
                ]
                selected = candidates[0] if candidates else root["manifests"][0]
                child_digest = selected.get("digest", "")
                if not DIGEST_RE.fullmatch(child_digest):
                    raise ValueError("invalid child manifest digest")
                child = client.get(
                    f"{scheme}://{registry}/v2/{repository}/manifests/{child_digest}",
                    headers={"Accept": accept},
                )
                child.raise_for_status()
                manifest = child.json()
            config_desc = manifest.get("config") or {}
            config_digest = config_desc.get("digest", "")
            config: dict[str, Any] = {}
            if DIGEST_RE.fullmatch(config_digest):
                blob = client.get(f"{scheme}://{registry}/v2/{repository}/blobs/{config_digest}")
                blob.raise_for_status()
                config = blob.json()
        size = int(config_desc.get("size", 0)) + sum(
            int(layer.get("size", 0)) for layer in manifest.get("layers", [])
        )
        image_config = config.get("config") or {}
        return ManifestInfo(
            digest=digest,
            size_bytes=size,
            labels={str(k): str(v) for k, v in (image_config.get("Labels") or {}).items()},
            environment=tuple(str(v) for v in (image_config.get("Env") or [])),
        )


class PatchPipeline:
    def __init__(
        self,
        db: Database,
        repo: AttackDefenseRepository,
        settings: AttackDefenseSettings,
        evidence: EvidenceRecorder,
        inspector: RegistryInspector,
        checker: HttpWorkflowChecker,
    ):
        self.db = db
        self.repo = repo
        self.settings = settings
        self.evidence = evidence
        self.inspector = inspector
        self.checker = checker

    def submit(
        self, match_id: str, team_id: str, service_id: str,
        image_reference: str, actor: str,
    ) -> dict:
        registry, repository, tag = parse_image_reference(image_reference)
        team = self.repo.get_team(team_id)
        service = self.repo.get_service(service_id)
        if not team or team["match_id"] != match_id:
            raise ValueError("unknown team")
        if not service or service["match_id"] != match_id:
            raise ValueError("unknown service")
        if registry != self.settings.allowed_registry:
            raise ValueError("registry_not_allowed")
        if tag == "latest":
            raise ValueError("latest_tag_forbidden")
        if not repository.startswith(f"{team['slug']}/{service['slug']}"):
            raise ValueError("team_registry_namespace_required")
        patch_id = str(uuid.uuid4())
        with self.db.transaction(immediate=True) as conn:
            now = self.db.server_time(conn)
            instance = self.repo.get_instance(match_id, team_id, service_id, conn)
            conn.execute(
                """INSERT INTO patch_submissions(
                   id,match_id,team_id,service_id,image_reference,previous_image_digest,
                   status,submitted_at) VALUES(?,?,?,?,?,?,'uploaded',?)""",
                (
                    patch_id, match_id, team_id, service_id, image_reference,
                    instance["image_digest"] if instance else None, now,
                ),
            )
            self.evidence.record(
                AuditContext(
                    actor=actor, event_type="patch_submission", result="uploaded",
                    team_id=team_id, match_id=match_id, service_id=service_id,
                    metadata={"patch_id": patch_id, "reference_hash": hashlib.sha256(
                        image_reference.encode()).hexdigest()},
                    event_id=stable_id("audit", "patch-submit", patch_id),
                ),
                conn,
            )
        return self.get(patch_id)

    def get(self, patch_id: str, conn: sqlite3.Connection | None = None) -> dict | None:
        owned = conn is None
        conn = conn or self.db.connect()
        row = conn.execute("SELECT * FROM patch_submissions WHERE id=?", (patch_id,)).fetchone()
        if owned:
            conn.close()
        return dict(row) if row else None

    def _transition(
        self, conn: sqlite3.Connection, patch: dict, target: str,
        result: dict | None = None,
    ) -> dict:
        if patch["status"] != target:
            assert_transition(patch["status"], target, PATCH_TRANSITIONS)
        now = self.db.server_time(conn)
        validated_at = now if target in {"approved", "rejected"} else patch.get("validated_at")
        deployed_at = now if target == "deployed" else patch.get("deployed_at")
        conn.execute(
            """UPDATE patch_submissions SET status=?,validation_result=?,
               validated_at=?,deployed_at=? WHERE id=? AND status=?""",
            (
                target, canonical_json(result or {}), validated_at, deployed_at,
                patch["id"], patch["status"],
            ),
        )
        row = conn.execute("SELECT * FROM patch_submissions WHERE id=?", (patch["id"],)).fetchone()
        return dict(row)

    def inspect_and_queue(self, patch_id: str, actor: str = "patch_pipeline") -> dict:
        patch = self.get(patch_id)
        if not patch:
            raise KeyError(patch_id)
        with self.db.transaction(immediate=True) as conn:
            patch = self._transition(conn, patch, PatchStatus.validating, {"stage": "policy_scan"})
        try:
            manifest = self.inspector.inspect(patch["image_reference"])
            violations = self._policy_violations(patch, manifest)
        except (ValueError, httpx.HTTPError) as exc:
            violations = [f"image_unavailable:{type(exc).__name__}"]
            manifest = None
        with self.db.transaction(immediate=True) as conn:
            current = self.get(patch_id, conn)
            if violations:
                current = self._transition(
                    conn, current, PatchStatus.rejected,
                    {"stage": "policy_scan", "violations": violations},
                )
                result = "rejected"
            else:
                registry, repository, _ = parse_image_reference(patch["image_reference"])
                pinned = f"{registry}/{repository}@{manifest.digest}"
                conn.execute(
                    "UPDATE patch_submissions SET image_reference=?,image_digest=? WHERE id=?",
                    (pinned, manifest.digest, patch_id),
                )
                current["image_reference"] = pinned
                current["image_digest"] = manifest.digest
                self._queue_job(
                    conn, operation="sandbox_validate", patch_id=patch_id,
                    patch=current, digest=manifest.digest,
                )
                result = "sandbox_queued"
            self.evidence.record(
                AuditContext(
                    actor=actor, event_type="patch_validation", result=result,
                    team_id=patch["team_id"], match_id=patch["match_id"],
                    service_id=patch["service_id"],
                    metadata={"patch_id": patch_id, "violations": violations},
                    event_id=stable_id("audit", "patch-policy", patch_id, result),
                ),
                conn,
            )
        return self.get(patch_id)

    def _policy_violations(self, patch: dict, manifest: ManifestInfo) -> list[str]:
        violations: list[str] = []
        if not DIGEST_RE.fullmatch(manifest.digest):
            violations.append("invalid_manifest_digest")
        if manifest.size_bytes > self.settings.patch_max_image_size_mb * 1024 * 1024:
            violations.append("image_too_large")
        service = self.repo.get_service(patch["service_id"])
        expected_lineage = service.get("base_image_digest") if service else None
        lineage = manifest.labels.get("org.cyber-range.base-digest", "")
        if expected_lineage and lineage != expected_lineage:
            violations.append("base_image_lineage_mismatch")
        unsafe_labels = {
            "org.cyber-range.privileged", "org.cyber-range.host-network",
            "org.cyber-range.host-mount", "org.cyber-range.cap-add",
        }
        if any(manifest.labels.get(k, "").lower() in {"1", "true", "yes"} for k in unsafe_labels):
            violations.append("dangerous_runtime_request")
        joined_env = "\n".join(manifest.environment).lower()
        if "docker.sock" in joined_env or "dump_secret" in joined_env:
            violations.append("suspicious_environment")
        if "checker" in joined_env and "bypass" in joined_env:
            violations.append("checker_bypass_marker")
        return violations

    def _queue_job(
        self, conn: sqlite3.Connection, operation: str, patch_id: str,
        patch: dict, digest: str,
    ) -> str:
        event_id = stable_id("runtime-job", operation, patch_id, digest)
        job_id = stable_id("job", event_id)
        instance = self.repo.get_instance(
            patch["match_id"], patch["team_id"], patch["service_id"], conn
        )
        now = self.db.server_time(conn)
        conn.execute(
            """INSERT OR IGNORE INTO runtime_jobs(
               id,event_id,operation,match_id,team_id,service_id,instance_id,payload,
               created_at) VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                job_id, event_id, operation, patch["match_id"], patch["team_id"],
                patch["service_id"], instance["id"] if instance else None,
                canonical_json({
                    "patch_id": patch_id, "image_digest": digest,
                    "image_reference": patch["image_reference"],
                    "previous_image_digest": patch.get("previous_image_digest"),
                    "runtime_id": "ad_patch_sandbox" if operation == "sandbox_validate"
                    else (instance["runtime_id"] if instance else ""),
                }),
                now,
            ),
        )
        return job_id

    def claim_job(self, owner: str) -> dict | None:
        with self.db.transaction(immediate=True) as conn:
            now = self.db.server_time(conn)
            stale_before = now - max(
                self.settings.patch_validation_timeout_seconds,
                self.settings.patch_deploy_timeout_seconds,
            )
            claim_sql = """SELECT * FROM runtime_jobs
                WHERE status='pending' OR (status='running' AND started_at<?)
                ORDER BY CASE status WHEN 'pending' THEN 0 ELSE 1 END,created_at
                LIMIT 1"""
            if self.db.backend_name == "postgresql":
                claim_sql += " FOR UPDATE SKIP LOCKED"
            row = conn.execute(
                claim_sql,
                (stale_before,),
            ).fetchone()
            if not row:
                return None
            previous_result = json.loads(row["result"] or "{}")
            attempt = int(previous_result.get("attempt", 0)) + 1
            claim_token = secrets.token_urlsafe(24)
            claimed_update = conn.execute(
                """UPDATE runtime_jobs SET status='running',started_at=?,result=?
                   WHERE id=? AND (
                     status='pending' OR (status='running' AND started_at<?)
                   )""",
                (
                    now, canonical_json({
                        "owner": owner, "attempt": attempt,
                        "claim_token": claim_token,
                    }),
                    row["id"], stale_before,
                ),
            )
            if claimed_update.rowcount != 1:
                return None
            claimed = conn.execute("SELECT * FROM runtime_jobs WHERE id=?", (row["id"],)).fetchone()
            return dict(claimed)

    def complete_job(
        self, job_id: str, success: bool, result: dict,
        actor: str = "runtime_runner", claim_token: str | None = None,
    ) -> dict:
        with self.db.transaction(immediate=True) as conn:
            job_row = conn.execute("SELECT * FROM runtime_jobs WHERE id=?", (job_id,)).fetchone()
            if not job_row or job_row["status"] != "running":
                raise ValueError("runtime job is not claimable")
            job = dict(job_row)
            if claim_token is not None:
                active_claim = str(json.loads(job["result"] or "{}").get(
                    "claim_token", ""
                ))
                if not active_claim or not hmac.compare_digest(
                    active_claim, claim_token
                ):
                    raise ValueError("runtime job claim is stale")
            payload = json.loads(job["payload"])
            now = self.db.server_time(conn)
            conn.execute(
                "UPDATE runtime_jobs SET status=?,result=?,completed_at=? WHERE id=?",
                ("completed" if success else "failed", canonical_json(result), now, job_id),
            )
            if job["operation"] in {"restart", "rollback_instance"}:
                if job["instance_id"]:
                    conn.execute(
                        """UPDATE team_service_instances SET status=?,updated_at=?,
                           image_digest=CASE WHEN ?='rollback_instance' AND ?=1
                             THEN previous_image_digest ELSE image_digest END
                           WHERE id=?""",
                        (
                            "healthy" if success else "degraded", now,
                            job["operation"], 1 if success else 0, job["instance_id"],
                        ),
                    )
                self.evidence.record(
                    AuditContext(
                        actor=actor, event_type=f"service_{job['operation']}",
                        result="success" if success else "failed", team_id=job["team_id"],
                        match_id=job["match_id"], service_id=job["service_id"],
                        metadata={"job_id": job_id},
                        event_id=stable_id("audit", "runtime-job", job_id, success),
                    ),
                    conn,
                )
                return {"job_id": job_id, "completed": success}
            patch = self.get(payload["patch_id"], conn)
            if job["operation"] == "sandbox_validate":
                if not success:
                    patch = self._transition(
                        conn, patch, PatchStatus.rejected,
                        {"stage": "sandbox_deploy", "category": "startup_failure"},
                    )
                else:
                    # Host runner has made the candidate available on the fixed,
                    # management-only sandbox endpoints. Functional verification
                    # is executed after this transaction by `verify_sandbox`.
                    pass
            elif job["operation"] == "deploy":
                if success:
                    endpoint = _runtime_endpoint(
                        result.get("endpoint"),
                        kubernetes=self.settings.game_runtime == "kubernetes",
                    )
                    management_endpoint = _runtime_endpoint(
                        result.get("management_endpoint"),
                        kubernetes=self.settings.game_runtime == "kubernetes",
                    )
                    if self.settings.game_runtime == "kubernetes" and (
                        not endpoint or not management_endpoint
                    ):
                        raise ValueError(
                            "successful Kubernetes deployment requires endpoints"
                        )
                    conn.execute(
                        """UPDATE team_service_instances SET previous_image_digest=image_digest,
                           image_digest=?,status='verifying',deployed_at=?,updated_at=?,
                           endpoint=COALESCE(?,endpoint),
                           management_endpoint=COALESCE(?,management_endpoint)
                           WHERE id=?""",
                        (
                            patch["image_digest"], now, now, endpoint,
                            management_endpoint, job["instance_id"],
                        ),
                    )
                else:
                    patch = self._transition(
                        conn, patch, PatchStatus.rollback,
                        {"stage": "deploy", "category": "deployment_failure"},
                    )
                    self._queue_job(
                        conn, "rollback", patch["id"], patch, patch["previous_image_digest"] or ""
                    )
            elif job["operation"] == "rollback":
                if success:
                    conn.execute(
                        """UPDATE team_service_instances
                           SET image_digest=previous_image_digest,
                               status='healthy',updated_at=? WHERE id=?""",
                        (now, job["instance_id"]),
                    )
                else:
                    conn.execute(
                        """UPDATE team_service_instances
                           SET status='degraded',updated_at=? WHERE id=?""",
                        (now, job["instance_id"]),
                    )
                if patch["status"] == PatchStatus.rollback:
                    patch = self._transition(
                        conn, patch, PatchStatus.failed,
                        {
                            "stage": "rollback",
                            "completed": success,
                            "category": (
                                "deployment_failure"
                                if success else "rollback_failure"
                            ),
                        },
                    )
            self.evidence.record(
                AuditContext(
                    actor=actor, event_type=f"patch_{job['operation']}",
                    result="success" if success else "failed", team_id=job["team_id"],
                    match_id=job["match_id"], service_id=job["service_id"],
                    metadata={"patch_id": patch["id"], "job_id": job_id},
                    event_id=stable_id("audit", "runtime-job", job_id, success),
                ),
                conn,
            )
        if job["operation"] == "sandbox_validate" and success:
            return self.verify_sandbox(
                payload["patch_id"], result.get("endpoint"),
                result.get("management_endpoint"),
            )
        if job["operation"] == "deploy" and success:
            return self.verify_live(payload["patch_id"])
        return self.get(payload["patch_id"])

    def verify_sandbox(
        self, patch_id: str, endpoint: str | None = None,
        management_endpoint: str | None = None,
    ) -> dict:
        patch = self.get(patch_id)
        service = self.repo.get_service(patch["service_id"])
        kubernetes = self.settings.game_runtime == "kubernetes"
        sandbox = {
            "id": "sandbox", "match_id": patch["match_id"],
            "team_id": patch["team_id"], "service_id": patch["service_id"],
            "endpoint": _runtime_endpoint(endpoint, kubernetes=kubernetes)
            or "http://ad_patch_sandbox:9000",
            "management_endpoint": _runtime_endpoint(
                management_endpoint, kubernetes=kubernetes
            ) or "http://ad_patch_sandbox:9001",
            "checker_type": service["checker_type"],
            "runtime_kind": "kubernetes" if kubernetes else "docker_compose",
            "management_secret_scope": f"sandbox-{patch_id}",
        }
        flag = SecretFlag(stable_id("sandbox-flag", patch_id), "FLAG{sandboxvalidationtoken000000000}")
        put = self.checker.injector.put_flag(sandbox, flag)
        outcomes = self.checker.run_all(sandbox, flag) if put.success else []
        passed = put.success and all(o.status == "ok" for o in outcomes)
        detail = {
            "stage": "functional_check",
            "put_flag": put.success,
            "checks": [{"type": o.check_type, "status": o.status} for o in outcomes],
        }
        with self.db.transaction(immediate=True) as conn:
            current = self.get(patch_id, conn)
            if not passed:
                current = self._transition(conn, current, PatchStatus.rejected, detail)
            else:
                current = self._transition(conn, current, PatchStatus.approved, detail)
                current = self._transition(conn, current, PatchStatus.deploying, detail)
                self._queue_job(
                    conn, "deploy", patch_id, current, current["image_digest"]
                )
        return self.get(patch_id)

    def verify_live(self, patch_id: str) -> dict:
        patch = self.get(patch_id)
        instance = self.repo.get_instance(
            patch["match_id"], patch["team_id"], patch["service_id"]
        )
        instance["runtime_kind"] = self.settings.game_runtime
        instance["management_secret_scope"] = "live"
        flag = SecretFlag(
            stable_id("post-deploy-flag", patch_id),
            "FLAG{postdeployvalidationtoken0000000}",
        )
        put = self.checker.injector.put_flag(instance, flag)
        outcomes = self.checker.run_all(instance, flag) if put.success else []
        passed = put.success and all(o.status == "ok" for o in outcomes)
        detail = {
            "stage": "post_deploy_check", "put_flag": put.success,
            "checks": [{"type": o.check_type, "status": o.status} for o in outcomes],
        }
        with self.db.transaction(immediate=True) as conn:
            current = self.get(patch_id, conn)
            now = self.db.server_time(conn)
            if passed:
                current = self._transition(conn, current, PatchStatus.deployed, detail)
                conn.execute(
                    "UPDATE team_service_instances SET status='healthy',updated_at=? WHERE id=?",
                    (now, instance["id"]),
                )
            else:
                current = self._transition(conn, current, PatchStatus.rollback, detail)
                conn.execute(
                    "UPDATE team_service_instances SET status='rollback',updated_at=? WHERE id=?",
                    (now, instance["id"]),
                )
                self._queue_job(
                    conn, "rollback", patch_id, current,
                    current["previous_image_digest"] or "",
                )
        return self.get(patch_id)

    def queue_instance_operation(
        self, match_id: str, team_id: str, service_id: str,
        operation: str, actor: str,
    ) -> dict:
        if operation not in {"restart", "rollback_instance"}:
            raise ValueError("unsupported runtime operation")
        instance = self.repo.get_instance(match_id, team_id, service_id)
        if not instance:
            raise ValueError("service instance not found")
        if operation == "rollback_instance" and not instance.get("previous_image_digest"):
            raise ValueError("no rollback target")
        event_id = stable_id(
            "runtime-job", operation, match_id, team_id, service_id,
            instance.get("previous_image_digest"),
        )
        job_id = stable_id("job", event_id)
        with self.db.transaction(immediate=True) as conn:
            now = self.db.server_time(conn)
            conn.execute(
                """INSERT OR IGNORE INTO runtime_jobs(
                   id,event_id,operation,match_id,team_id,service_id,instance_id,payload,
                   created_at) VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    job_id, event_id, operation, match_id, team_id, service_id,
                    instance["id"], canonical_json({
                        "runtime_id": instance["runtime_id"],
                        "previous_image_digest": instance.get("previous_image_digest"),
                    }), now,
                ),
            )
            conn.execute(
                "UPDATE team_service_instances SET status=?,updated_at=? WHERE id=?",
                ("restarting" if operation == "restart" else "rollback", now, instance["id"]),
            )
            self.evidence.record(
                AuditContext(
                    actor=actor, event_type=f"service_{operation}", result="queued",
                    team_id=team_id, match_id=match_id, service_id=service_id,
                    metadata={"job_id": job_id},
                    event_id=stable_id("audit", "queue", job_id),
                ),
                conn,
            )
        return {"job_id": job_id, "status": "pending"}
