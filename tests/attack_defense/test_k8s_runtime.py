"""
Kubernetes 런타임 어댑터(roadmap #2) 계약 고정 — 매니페스트 생성·정책 검증·ServiceRuntime.
per-team namespace·digest 고정 이미지·비루트 securityContext·default-deny NetworkPolicy·
ResourceQuota·readiness 게이팅. 클러스터 없이 dry-run 으로 검증.
"""
import pytest

from services.attack_defense.k8s_runtime import (
    build_manifests, validate_manifests, namespace_for, KubernetesRuntime,
)

INSTANCE = {
    "id": "inst-1", "runtime_id": "notes-red",
    "match_id": "m1", "team_slug": "red", "service_slug": "notes",
    "image": "registry.local:5000/notes",
    "image_digest": "sha256:" + "a" * 64,
    "container_port": 8080,
}


def test_namespace_is_per_team_scoped():
    assert namespace_for(INSTANCE) == "ad-m1-red"


def test_build_manifests_produces_expected_kinds():
    m = build_manifests(INSTANCE, allowed_registry="registry.local:5000")
    kinds = {v["kind"] for v in m.values()}
    assert {"Namespace", "Deployment", "Service", "NetworkPolicy", "ResourceQuota"} <= kinds


def test_deployment_image_is_digest_pinned():
    m = build_manifests(INSTANCE, allowed_registry="registry.local:5000")
    img = m["deployment"]["spec"]["template"]["spec"]["containers"][0]["image"]
    assert img == "registry.local:5000/notes@sha256:" + "a" * 64


def test_deployment_security_context_hardened():
    c = build_manifests(INSTANCE, allowed_registry="registry.local:5000")["deployment"]
    spec = c["spec"]["template"]["spec"]
    sc = spec["containers"][0]["securityContext"]
    assert sc["runAsNonRoot"] and sc["readOnlyRootFilesystem"]
    assert sc["allowPrivilegeEscalation"] is False
    assert sc["capabilities"]["drop"] == ["ALL"]
    assert spec["containers"][0]["readinessProbe"]["httpGet"]["path"] == "/health"


def test_networkpolicy_default_deny():
    np = build_manifests(INSTANCE, allowed_registry="registry.local:5000")["networkpolicy"]
    assert set(np["spec"]["policyTypes"]) == {"Ingress", "Egress"}


def test_validate_rejects_non_digest_image():
    bad = dict(INSTANCE, image_digest="latest")
    m = build_manifests(bad, allowed_registry="registry.local:5000")
    v = validate_manifests(m, allowed_registry="registry.local:5000")
    assert "image_not_digest_pinned" in v


def test_validate_rejects_wrong_registry():
    bad = dict(INSTANCE, image="ghcr.io/evil/notes")
    m = build_manifests(bad, allowed_registry="registry.local:5000")
    v = validate_manifests(m, allowed_registry="registry.local:5000")
    assert "registry_not_allowed" in v


def test_validate_passes_clean():
    m = build_manifests(INSTANCE, allowed_registry="registry.local:5000")
    assert validate_manifests(m, allowed_registry="registry.local:5000") == []


# ── ServiceRuntime 어댑터(dry-run) ────────────────────────────────────────
def test_runtime_deploy_success_dry_run():
    rt = KubernetesRuntime(allowed_registry="registry.local:5000", dry_run=True)
    r = rt.deploy(INSTANCE)
    assert r.success and r.image_digest == INSTANCE["image_digest"]


def test_runtime_deploy_fails_on_bad_image():
    rt = KubernetesRuntime(allowed_registry="registry.local:5000", dry_run=True)
    r = rt.deploy(dict(INSTANCE, image_digest="latest"))
    assert not r.success and r.error_code == "manifest_policy_violation"


def test_runtime_replace_image_digest_pinned():
    rt = KubernetesRuntime(allowed_registry="registry.local:5000", dry_run=True)
    new = "sha256:" + "b" * 64
    r = rt.replace_image(INSTANCE, new)
    assert r.success and r.image_digest == new


def test_runtime_replace_rejects_non_digest():
    rt = KubernetesRuntime(allowed_registry="registry.local:5000", dry_run=True)
    r = rt.replace_image(INSTANCE, "v2-tag")
    assert not r.success
