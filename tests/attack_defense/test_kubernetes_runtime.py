from __future__ import annotations

import base64
import copy
import json
import subprocess
import time

import jwt
import pytest
from fastapi.testclient import TestClient

from services.attack_defense.api import create_app
from services.attack_defense.checker import derive_management_token
from services.attack_defense.kubernetes_runtime import (
    KubernetesRuntime,
    KubernetesRuntimeConfig,
    build_manifests,
    map_image_registry,
    namespace_for,
    pinned_image,
    validate_manifests,
)

from .conftest import bootstrap

DIGEST = "sha256:" + "a" * 64
JWT_SECRET = "unit-test-jwt-secret-with-enough-entropy"


def config(*, dry_run: bool = True) -> KubernetesRuntimeConfig:
    return KubernetesRuntimeConfig(
        allowed_registry="registry.local:5000",
        image_registry="registry.cluster:5000",
        management_master_token="management-master-for-tests",
        context="range-cluster" if not dry_run else "",
        dry_run=dry_run,
    )


def instance(*, sandbox: bool = False) -> dict:
    value = {
        "id": "instance-1", "runtime_id": "team-01-vulnerable-notes",
        "match_id": "match-1", "team_id": "team-1", "team_slug": "team-01",
        "service_id": "service-notes", "service_slug": "vulnerable-notes",
        "base_image": "registry.cluster:5000/base/vulnerable-notes:v1",
        "base_image_digest": DIGEST, "image_digest": DIGEST,
        "internal_port": 9000,
        "service_config": json.dumps({
            "management_port": 9001, "health_path": "/health",
        }),
    }
    if sandbox:
        value.update({
            "sandbox": True, "runtime_id": "sandbox-patch-1",
            "management_secret_scope": "sandbox-patch-1",
        })
    return value


def test_live_bundle_is_digest_pinned_isolated_and_restricted():
    cfg = config()
    resources = build_manifests(instance(), cfg)
    assert validate_manifests(resources, cfg, sandbox=False) == ()
    by_kind = {resource["kind"]: resource for resource in resources}
    namespace = by_kind["Namespace"]
    assert namespace["metadata"]["labels"][
        "pod-security.kubernetes.io/enforce"
    ] == "restricted"
    deployment = by_kind["Deployment"]
    pod = deployment["spec"]["template"]["spec"]
    container = pod["containers"][0]
    assert container["image"].endswith(f"@{DIGEST}")
    assert pod["automountServiceAccountToken"] is False
    assert pod["hostNetwork"] is False
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert container["securityContext"]["capabilities"] == {"drop": ["ALL"]}
    assert "value" not in next(
        env for env in container["env"]
        if env["name"] == "ATTACK_DEFENSE_MANAGEMENT_TOKEN"
    )
    assert by_kind["PersistentVolumeClaim"]["spec"]["accessModes"] == [
        "ReadWriteMany"
    ]
    policies = [r for r in resources if r["kind"] == "NetworkPolicy"]
    assert any(p["metadata"]["name"] == "default-deny-all" for p in policies)
    assert any(p["metadata"]["name"].endswith("game-ingress") for p in policies)


def test_patch_sandbox_has_no_persistence_or_game_ingress():
    cfg = config()
    live = instance()
    sandbox = instance(sandbox=True)
    resources = build_manifests(sandbox, cfg)
    assert validate_manifests(resources, cfg, sandbox=True) == ()
    assert not any(r["kind"] == "PersistentVolumeClaim" for r in resources)
    names = {
        r["metadata"]["name"] for r in resources if r["kind"] == "NetworkPolicy"
    }
    assert not any(name.endswith("game-ingress") for name in names)
    assert namespace_for(live, cfg) != namespace_for(sandbox, cfg)
    assert derive_management_token(
        cfg.management_master_token, {**live, "management_secret_scope": "live"}
    ) != derive_management_token(cfg.management_master_token, sandbox)


def test_manifest_policy_rejects_host_mount_plain_secret_and_unsafe_rollout():
    cfg = config()
    resources = build_manifests(instance(), cfg)
    deployment = next(r for r in resources if r["kind"] == "Deployment")
    tampered = copy.deepcopy(resources)
    pod = next(r for r in tampered if r["kind"] == "Deployment")["spec"][
        "template"
    ]["spec"]
    pod["volumes"].append({"name": "host", "hostPath": {"path": "/"}})
    pod["containers"][0]["env"].append({
        "name": "ATTACK_DEFENSE_MANAGEMENT_TOKEN", "value": "leaked",
    })
    next(r for r in tampered if r["kind"] == "Deployment")["spec"][
        "strategy"
    ]["rollingUpdate"]["maxUnavailable"] = 1
    violations = validate_manifests(tampered, cfg, sandbox=False)
    assert "host_path_forbidden" in violations
    assert "plaintext_management_secret_forbidden" in violations
    assert "safe_rollout_strategy_required" in violations
    assert deployment["kind"] == "Deployment"


def test_image_mapping_and_digest_requirement():
    assert map_image_registry(
        "registry.local:5000/team/image@" + DIGEST,
        "registry.local:5000", "registry.cluster:5000",
    ).startswith("registry.cluster:5000/")
    assert pinned_image(instance()).endswith(f"@{DIGEST}")
    with pytest.raises(ValueError, match="pinned"):
        pinned_image({"base_image": "registry.cluster:5000/base/image:latest"})


def test_runtime_config_rejects_unsafe_context_dependencies():
    with pytest.raises(ValueError, match="registry"):
        KubernetesRuntimeConfig(
            allowed_registry="registry.local:5000/extra",
            image_registry="registry.cluster:5000",
            management_master_token="secret",
        ).validate()
    with pytest.raises(ValueError, match="kubectl"):
        KubernetesRuntimeConfig(
            allowed_registry="registry.local:5000",
            image_registry="registry.cluster:5000",
            management_master_token="secret", kubectl_binary="kubectl --evil",
        ).validate()
    with pytest.raises(ValueError, match="context"):
        KubernetesRuntimeConfig(
            allowed_registry="registry.local:5000",
            image_registry="registry.cluster:5000",
            management_master_token="secret", dry_run=False,
        ).validate()


def test_runtime_dry_run_returns_cluster_dns_without_executing_kubectl():
    called = []

    def runner(*args, **kwargs):
        called.append((args, kwargs))
        raise AssertionError("dry-run must not call kubectl")

    result = KubernetesRuntime(config(), runner=runner).deploy(instance())
    assert result.success is True
    assert ":" in result.runtime_id
    assert result.endpoint and result.endpoint.endswith(".svc:9000")
    assert result.management_endpoint and result.management_endpoint.endswith(
        ".svc:9001"
    )
    assert called == []


def test_runtime_apply_uses_explicit_context_stdin_and_readiness_gate():
    calls: list[tuple[list[str], str | None]] = []

    def runner(command, *, input_text, timeout):
        calls.append((command, input_text))
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    cfg = config(dry_run=False)
    result = KubernetesRuntime(cfg, runner=runner).deploy(instance())
    assert result.success is True
    assert len(calls) == 3
    assert all("--context" in command for command, _ in calls)
    assert all("range-cluster" in command for command, _ in calls)
    assert calls[0][1] and '"kind":"Namespace"' in calls[0][1]
    assert calls[1][1] and '"kind":"List"' in calls[1][1]
    assert calls[2][1] is None
    token = derive_management_token(cfg.management_master_token, {
        **instance(), "management_secret_scope": "live",
        "runtime_kind": "kubernetes",
    })
    assert all(token not in " ".join(command) for command, _ in calls)
    assert base64.b64encode(token.encode()).decode() in calls[1][1]


def test_runtime_fails_closed_when_rollout_does_not_become_ready():
    def runner(command, *, input_text, timeout):
        code = 1 if "rollout" in command else 0
        return subprocess.CompletedProcess(command, code, stdout="", stderr="failed")

    result = KubernetesRuntime(config(dry_run=False), runner=runner).deploy(instance())
    assert result.success is False
    assert result.error_code == "rollout_not_ready"


def _token(role: str, team_id: str = "", match_id: str = "") -> str:
    return jwt.encode({
        "sub": f"{role}-user", "role": role, "team_id": team_id,
        "match_id": match_id, "type": "access", "exp": int(time.time()) + 300,
    }, JWT_SECRET, algorithm="HS256")


def test_operator_records_reconcile_result_and_competitor_is_denied(ad, monkeypatch):
    bootstrap(ad, teams=1, services=1)
    monkeypatch.setenv("AUTH_JWT_SECRET", JWT_SECRET)
    client = TestClient(create_app(ad))
    instance_row = ad.repo.list_instances("match-1")[0]
    body = {
        "success": True, "runtime_id": "vulnerable-notes-runtime",
        "endpoint": "http://vulnerable-notes:9000",
        "management_endpoint": "http://vulnerable-notes:9001",
        "image_digest": DIGEST, "reason": "initial cluster reconciliation",
    }
    competitor = {"Authorization": f"Bearer {_token('competitor', 'team-1', 'match-1')}"}
    path = (
        f"/api/attack-defense/operator/matches/match-1/instances/"
        f"{instance_row['id']}/runtime-result"
    )
    assert client.post(path, headers=competitor, json=body).status_code == 403
    operator = {"Authorization": f"Bearer {_token('operator')}"}
    response = client.post(path, headers=operator, json=body)
    assert response.status_code == 200
    updated = ad.repo.get_instance(
        "match-1", "team-1", "service-vulnerable-notes"
    )
    assert updated["status"] == "healthy"
    assert updated["endpoint"] == body["endpoint"]
    conn = ad.db.connect()
    audit = conn.execute(
        "SELECT metadata FROM audit_events WHERE event_type='runtime_reconcile'"
    ).fetchone()
    conn.close()
    assert "initial cluster reconciliation" in audit["metadata"]
