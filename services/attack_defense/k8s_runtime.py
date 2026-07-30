"""
Kubernetes 런타임 어댑터 (roadmap #2)
======================================
`ServiceRuntime` 프로토콜의 Kubernetes 구현. Compose 로는 표현 불가한 토너먼트급 격리를 위해
per-team namespace, default-deny NetworkPolicy, ResourceQuota, readiness 게이팅 롤아웃,
digest 고정(불변) 이미지, 비루트 하드닝 securityContext 를 매니페스트로 생성한다.

보안 모델: API 컨테이너는 클러스터를 직접 제어하지 않는다(root-equivalent 금지). 이 어댑터는
매니페스트를 생성·정책 검증하고(dry-run), 신뢰된 host 러너/CI 가 kubectl 로 적용한다. 실제 적용
경로(kubectl)는 apply_fn 주입으로 열어 두되 기본은 dry-run 이다.

매니페스트 생성은 순수 함수라 클러스터 없이 단위 테스트가 가능하다.
"""
from __future__ import annotations

import re
from typing import Any, Callable

from .service_fabric import RuntimeResult

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE = re.compile(r"[^a-z0-9-]")


def _san(name: str) -> str:
    return _SAFE.sub("-", str(name).lower()).strip("-") or "x"


def namespace_for(instance: dict) -> str:
    """per-team namespace(팀 격리): ad-<match>-<team>."""
    return f"ad-{_san(instance.get('match_id', 'm'))}-{_san(instance.get('team_slug', 't'))}"


def _pinned_image(instance: dict) -> str:
    return f"{instance.get('image', 'app')}@{instance.get('image_digest', '')}"


def build_manifests(instance: dict, allowed_registry: str) -> dict[str, dict]:
    """서비스 인스턴스 → k8s 매니페스트 번들(namespace/deployment/service/networkpolicy/resourcequota)."""
    ns = namespace_for(instance)
    name = _san(instance.get("service_slug") or instance.get("runtime_id") or instance["id"])
    port = int(instance.get("container_port", 8080))
    labels = {"app": name, "ad-match": _san(instance.get("match_id", "")),
              "ad-team": _san(instance.get("team_slug", ""))}

    namespace = {"apiVersion": "v1", "kind": "Namespace",
                 "metadata": {"name": ns, "labels": {"ad-plane": "game"}}}

    deployment = {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": name, "namespace": ns, "labels": labels},
        "spec": {
            "replicas": 1,
            "strategy": {"type": "RollingUpdate",
                         "rollingUpdate": {"maxUnavailable": 0, "maxSurge": 1}},  # readiness-gated
            "selector": {"matchLabels": {"app": name}},
            "template": {
                "metadata": {"labels": labels},
                "spec": {
                    "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [{
                        "name": name,
                        "image": _pinned_image(instance),
                        "imagePullPolicy": "IfNotPresent",
                        "ports": [{"containerPort": port}],
                        "securityContext": {
                            "runAsNonRoot": True, "readOnlyRootFilesystem": True,
                            "allowPrivilegeEscalation": False,
                            "capabilities": {"drop": ["ALL"]},
                        },
                        "readinessProbe": {"httpGet": {"path": "/health", "port": port},
                                           "initialDelaySeconds": 3, "periodSeconds": 5},
                        "livenessProbe": {"httpGet": {"path": "/health", "port": port},
                                          "initialDelaySeconds": 10, "periodSeconds": 10},
                        "resources": {"requests": {"cpu": "100m", "memory": "128Mi"},
                                      "limits": {"cpu": "500m", "memory": "256Mi"}},
                    }],
                },
            },
        },
    }

    service = {"apiVersion": "v1", "kind": "Service",
               "metadata": {"name": name, "namespace": ns, "labels": labels},
               "spec": {"type": "ClusterIP", "selector": {"app": name},
                        "ports": [{"port": port, "targetPort": port}]}}

    # default-deny + 게임/스코어보드 컨트롤 플레인에서의 제한적 ingress·egress 만 허용
    networkpolicy = {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": f"{name}-default-deny", "namespace": ns},
        "spec": {
            "podSelector": {"matchLabels": {"app": name}},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [{"from": [{"namespaceSelector": {"matchLabels": {"ad-plane": "game"}}}],
                         "ports": [{"protocol": "TCP", "port": port}]}],
            "egress": [{"to": [{"namespaceSelector": {"matchLabels": {"ad-plane": "management"}}}]},
                       {"ports": [{"protocol": "UDP", "port": 53}]}],  # DNS only
        },
    }

    resourcequota = {"apiVersion": "v1", "kind": "ResourceQuota",
                     "metadata": {"name": "ad-team-quota", "namespace": ns},
                     "spec": {"hard": {"pods": "8", "requests.cpu": "2", "requests.memory": "2Gi",
                                       "limits.cpu": "4", "limits.memory": "4Gi"}}}

    return {"namespace": namespace, "deployment": deployment, "service": service,
            "networkpolicy": networkpolicy, "resourcequota": resourcequota}


def validate_manifests(manifests: dict[str, dict], allowed_registry: str) -> list[str]:
    """정책 검증: digest 고정 이미지·허용 레지스트리·비루트·default-deny·quota. 위반 코드 리스트."""
    v: list[str] = []
    dep = manifests.get("deployment", {})
    container = (dep.get("spec", {}).get("template", {}).get("spec", {}).get("containers") or [{}])[0]
    image = container.get("image", "")
    if "@" not in image or not _DIGEST_RE.match(image.split("@", 1)[-1]):
        v.append("image_not_digest_pinned")
    repo = image.split("@", 1)[0]
    if allowed_registry and not repo.startswith(allowed_registry):
        v.append("registry_not_allowed")
    sc = container.get("securityContext", {})
    if not sc.get("runAsNonRoot") or not sc.get("readOnlyRootFilesystem") \
            or sc.get("allowPrivilegeEscalation") is not False:
        v.append("container_not_hardened")
    np = manifests.get("networkpolicy", {})
    if set(np.get("spec", {}).get("policyTypes", [])) != {"Ingress", "Egress"}:
        v.append("networkpolicy_not_default_deny")
    if "resourcequota" not in manifests:
        v.append("resourcequota_missing")
    return v


class KubernetesRuntime:
    """ServiceRuntime 의 Kubernetes 구현. 기본 dry-run(매니페스트 생성·검증만). apply_fn 주입 시
    신뢰된 러너가 kubectl apply 하도록 위임할 수 있다(멱등)."""

    def __init__(self, allowed_registry: str, dry_run: bool = True,
                 apply_fn: Callable[[dict[str, dict]], bool] | None = None):
        self.allowed_registry = allowed_registry
        self.dry_run = dry_run
        self.apply_fn = apply_fn

    def _result(self, instance: dict, digest: str | None = None) -> RuntimeResult:
        manifests = build_manifests(
            dict(instance, image_digest=digest or instance.get("image_digest", "")),
            self.allowed_registry)
        violations = validate_manifests(manifests, self.allowed_registry)
        rid = instance.get("runtime_id") or instance["id"]
        if violations:
            return RuntimeResult(False, rid, error_code="manifest_policy_violation")
        applied = True
        if not self.dry_run and self.apply_fn is not None:
            applied = bool(self.apply_fn(manifests))
        endpoint = f"http://{_san(instance.get('service_slug') or rid)}.{namespace_for(instance)}.svc:" \
                   f"{int(instance.get('container_port', 8080))}"
        return RuntimeResult(applied, rid, endpoint,
                             digest or instance.get("image_digest"),
                             None if applied else "apply_failed")

    def deploy(self, instance: dict) -> RuntimeResult:
        return self._result(instance)

    def restart(self, instance: dict) -> RuntimeResult:
        return self._result(instance)

    def inspect(self, instance: dict) -> RuntimeResult:
        return self._result(instance)

    def stop(self, instance: dict) -> RuntimeResult:
        return RuntimeResult(True, instance.get("runtime_id") or instance["id"])

    def replace_image(self, instance: dict, image_digest: str) -> RuntimeResult:
        if not _DIGEST_RE.match(image_digest or ""):
            return RuntimeResult(False, instance.get("runtime_id") or instance["id"],
                                 image_digest=image_digest, error_code="image_not_digest_pinned")
        return self._result(instance, digest=image_digest)

    def get_endpoint(self, instance: dict) -> str:
        rid = instance.get("runtime_id") or instance["id"]
        return f"http://{_san(instance.get('service_slug') or rid)}.{namespace_for(instance)}.svc:" \
               f"{int(instance.get('container_port', 8080))}"
