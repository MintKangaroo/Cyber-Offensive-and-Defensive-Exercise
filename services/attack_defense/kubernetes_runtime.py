from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .checker import derive_management_token
from .service_fabric import RuntimeResult

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CONTEXT_RE = re.compile(r"^[A-Za-z0-9._:@/-]{1,200}$")
_PREFIX_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,19}$")
_REGISTRY_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?(?::[0-9]{1,5})?$"
)
_BINARY_RE = re.compile(r"^(?:[A-Za-z0-9._-]+|(?:/[A-Za-z0-9._-]+)+)$")
_STORAGE_CLASS_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$"
)
_QUANTITY_RE = re.compile(r"^[0-9]+(?:m|Ki|Mi|Gi)?$")
_HEALTH_PATH_RE = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,127}$")
_ALLOWED_KINDS = {
    "Namespace", "ResourceQuota", "LimitRange", "ServiceAccount", "Secret",
    "PersistentVolumeClaim", "NetworkPolicy", "Deployment", "Service",
    "PodDisruptionBudget",
}


@dataclass(frozen=True)
class KubernetesRuntimeConfig:
    allowed_registry: str
    image_registry: str
    management_master_token: str
    context: str = ""
    kubeconfig: Path | None = None
    kubectl_binary: str = "kubectl"
    namespace_prefix: str = "ad"
    field_manager: str = "cyber-range-ad-runtime"
    rollout_timeout_seconds: int = 180
    pod_security_version: str = "latest"
    storage_class: str = ""
    storage_size: str = "1Gi"
    pvc_access_mode: str = "ReadWriteMany"
    cpu_request: str = "100m"
    cpu_limit: str = "500m"
    memory_request: str = "128Mi"
    memory_limit: str = "512Mi"
    manage_namespaces: bool = True
    dry_run: bool = True

    def validate(self) -> None:
        if not _PREFIX_RE.fullmatch(self.namespace_prefix):
            raise ValueError("invalid Kubernetes namespace prefix")
        for registry in (self.allowed_registry, self.image_registry):
            if not _REGISTRY_RE.fullmatch(registry):
                raise ValueError("invalid Kubernetes registry")
            _, separator, port = registry.rpartition(":")
            if separator and (not port.isdigit() or int(port) > 65535):
                raise ValueError("invalid Kubernetes registry port")
        if not self.management_master_token:
            raise ValueError("Kubernetes management secret master is required")
        if not _BINARY_RE.fullmatch(self.kubectl_binary):
            raise ValueError("invalid kubectl binary")
        if not self.dry_run and not _CONTEXT_RE.fullmatch(self.context):
            raise ValueError("an explicit Kubernetes context is required for apply")
        if self.kubeconfig is not None and not Path(self.kubeconfig).is_file():
            raise ValueError("Kubernetes kubeconfig not found")
        if not _CONTEXT_RE.fullmatch(self.field_manager):
            raise ValueError("invalid Kubernetes field manager")
        if not re.fullmatch(r"(?:latest|v[0-9]+\.[0-9]+)", self.pod_security_version):
            raise ValueError("invalid Pod Security Admission version")
        if self.pvc_access_mode not in {"ReadWriteOnce", "ReadWriteMany"}:
            raise ValueError("unsupported PVC access mode")
        if self.storage_class and not _STORAGE_CLASS_RE.fullmatch(self.storage_class):
            raise ValueError("invalid Kubernetes storage class")
        for value in (
            self.storage_size, self.cpu_request, self.cpu_limit,
            self.memory_request, self.memory_limit,
        ):
            if not _QUANTITY_RE.fullmatch(value):
                raise ValueError("invalid Kubernetes resource quantity")
        if self.rollout_timeout_seconds < 10:
            raise ValueError("Kubernetes rollout timeout must be at least 10 seconds")


def _dns_label(value: object, maximum: int = 63) -> str:
    original = str(value).lower()
    readable = re.sub(r"[^a-z0-9-]+", "-", original).strip("-") or "x"
    digest = hashlib.sha256(original.encode()).hexdigest()[:8]
    return f"{readable[:maximum - 9].rstrip('-') or 'x'}-{digest}"


def _label_value(value: object) -> str:
    return _dns_label(value, 63)


def namespace_for(instance: dict[str, Any], config: KubernetesRuntimeConfig) -> str:
    if instance.get("sandbox"):
        value = (
            f"{config.namespace_prefix}-sandbox-{instance.get('match_id')}-"
            f"{instance.get('team_slug')}-{instance.get('service_slug')}-"
            f"{instance.get('management_secret_scope', 'candidate')}"
        )
    else:
        value = (
            f"{config.namespace_prefix}-{instance.get('match_id')}-"
            f"{instance.get('team_slug')}"
        )
    return _dns_label(value)


def deployment_name(instance: dict[str, Any]) -> str:
    value = instance.get("service_slug") or instance.get("runtime_id") or instance.get("id")
    if instance.get("sandbox"):
        value = f"{value}-sandbox"
    return _dns_label(value)


def _repository(reference: str) -> str:
    value = reference.split("@", 1)[0]
    slash = value.rfind("/")
    colon = value.rfind(":")
    if colon > slash:
        value = value[:colon]
    return value


def map_image_registry(reference: str, source: str, target: str) -> str:
    prefix = f"{source.rstrip('/')}/"
    if reference.startswith(prefix):
        return f"{target.rstrip('/')}/{reference[len(prefix):]}"
    return reference


def pinned_image(instance: dict[str, Any], candidate: str | None = None) -> str:
    value = str(candidate or instance.get("image_reference") or "")
    if "@" in value:
        repository, digest = value.rsplit("@", 1)
    elif _DIGEST_RE.fullmatch(value):
        repository = _repository(str(
            instance.get("image_repository") or instance.get("base_image") or ""
        ))
        digest = value
    else:
        digest = str(instance.get("image_digest") or instance.get("base_image_digest") or "")
        repository = _repository(value or str(instance.get("base_image") or ""))
    if not repository or not _DIGEST_RE.fullmatch(digest):
        raise ValueError("image must be pinned by sha256 digest")
    return f"{repository}@{digest}"


def _service_config(instance: dict[str, Any]) -> dict[str, Any]:
    value = instance.get("service_config") or {}
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    return value if isinstance(value, dict) else {}


def build_manifests(
    instance: dict[str, Any], config: KubernetesRuntimeConfig,
    image_reference: str | None = None,
) -> list[dict[str, Any]]:
    config.validate()
    namespace = namespace_for(instance, config)
    name = deployment_name(instance)
    service_config = _service_config(instance)
    game_port = int(instance.get("internal_port") or instance.get("container_port") or 9000)
    management_port = int(service_config.get("management_port", 9001))
    if not 1 <= game_port <= 65535 or not 1 <= management_port <= 65535:
        raise ValueError("invalid Kubernetes service port")
    health_path = str(service_config.get("health_path", "/health"))
    if not _HEALTH_PATH_RE.fullmatch(health_path):
        raise ValueError("invalid Kubernetes health path")
    image = pinned_image(instance, image_reference)
    registry = image.split("/", 1)[0]
    if registry != config.image_registry:
        raise ValueError("image registry is not allowed for Kubernetes")

    sandbox = bool(instance.get("sandbox"))
    secret_scope = str(instance.get("management_secret_scope") or (
        f"sandbox-{instance.get('runtime_id')}" if sandbox else "live"
    ))
    secret_instance = {
        **instance, "management_secret_scope": secret_scope,
        "runtime_kind": "kubernetes",
    }
    management_token = derive_management_token(
        config.management_master_token, secret_instance
    )
    secret_fingerprint = hashlib.sha256(management_token.encode()).hexdigest()[:10]
    secret_name = _dns_label(f"{name}-management-{secret_fingerprint}")
    pvc_name = _dns_label(f"{name}-data")
    labels = {
        "app.kubernetes.io/name": name,
        "app.kubernetes.io/managed-by": "cyber-range-ad-runtime",
        "ad.cyber-range/plane": "game-service" if not sandbox else "patch-sandbox",
        "ad.cyber-range/match": _label_value(instance.get("match_id", "match")),
        "ad.cyber-range/team": _label_value(instance.get("team_slug", "team")),
        "ad.cyber-range/service": _label_value(instance.get("service_slug", name)),
    }
    selector = {
        "app.kubernetes.io/name": name,
        "ad.cyber-range/match": labels["ad.cyber-range/match"],
        "ad.cyber-range/team": labels["ad.cyber-range/team"],
    }
    namespace_labels = {
        "app.kubernetes.io/managed-by": "cyber-range-ad-runtime",
        "ad.cyber-range/plane": "patch-sandbox" if sandbox else "game-team",
        "ad.cyber-range/match": labels["ad.cyber-range/match"],
        "ad.cyber-range/team": labels["ad.cyber-range/team"],
        "pod-security.kubernetes.io/enforce": "restricted",
        "pod-security.kubernetes.io/enforce-version": config.pod_security_version,
        "pod-security.kubernetes.io/audit": "restricted",
        "pod-security.kubernetes.io/warn": "restricted",
    }

    resources: list[dict[str, Any]] = [
        {
            "apiVersion": "v1", "kind": "Namespace",
            "metadata": {"name": namespace, "labels": namespace_labels},
        },
        {
            "apiVersion": "v1", "kind": "ResourceQuota",
            "metadata": {"name": "ad-team-quota", "namespace": namespace},
            "spec": {"hard": {
                "pods": "12", "requests.cpu": "4", "requests.memory": "4Gi",
                "limits.cpu": "8", "limits.memory": "8Gi",
                "persistentvolumeclaims": "8",
            }},
        },
        {
            "apiVersion": "v1", "kind": "LimitRange",
            "metadata": {"name": "ad-container-limits", "namespace": namespace},
            "spec": {"limits": [{
                "type": "Container",
                "defaultRequest": {
                    "cpu": config.cpu_request, "memory": config.memory_request,
                },
                "default": {"cpu": config.cpu_limit, "memory": config.memory_limit},
            }]},
        },
        {
            "apiVersion": "v1", "kind": "ServiceAccount",
            "metadata": {"name": name, "namespace": namespace},
            "automountServiceAccountToken": False,
        },
        {
            "apiVersion": "v1", "kind": "Secret",
            "metadata": {"name": secret_name, "namespace": namespace},
            "type": "Opaque", "immutable": True,
            "data": {"management-token": base64.b64encode(
                management_token.encode()
            ).decode()},
        },
    ]
    if not sandbox:
        pvc_spec: dict[str, Any] = {
            "accessModes": [config.pvc_access_mode],
            "resources": {"requests": {"storage": config.storage_size}},
        }
        if config.storage_class:
            pvc_spec["storageClassName"] = config.storage_class
        resources.append({
            "apiVersion": "v1", "kind": "PersistentVolumeClaim",
            "metadata": {"name": pvc_name, "namespace": namespace},
            "spec": pvc_spec,
        })

    resources.append({
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": "default-deny-all", "namespace": namespace},
        "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]},
    })
    if not sandbox:
        resources.append({
            "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": f"{name}-game-ingress", "namespace": namespace},
            "spec": {
                "podSelector": {"matchLabels": selector},
                "policyTypes": ["Ingress"],
                "ingress": [{
                    "from": [{"namespaceSelector": {"matchExpressions": [{
                        "key": "ad.cyber-range/plane", "operator": "In",
                        "values": ["game-team", "game-attack"],
                    }]}}],
                    "ports": [{"protocol": "TCP", "port": game_port}],
                }],
            },
        })
    resources.append({
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": f"{name}-management-ingress", "namespace": namespace},
        "spec": {
            "podSelector": {"matchLabels": selector},
            "policyTypes": ["Ingress"],
            "ingress": [{
                "from": [{
                    "namespaceSelector": {"matchLabels": {
                        "ad.cyber-range/plane": "management",
                    }},
                    "podSelector": {"matchExpressions": [{
                        "key": "ad.cyber-range/component", "operator": "In",
                        "values": ["api", "checker", "flag-injector"],
                    }]},
                }],
                "ports": [
                    {"protocol": "TCP", "port": game_port},
                    {"protocol": "TCP", "port": management_port},
                ],
            }],
        },
    })

    data_volume = (
        {"name": "service-data", "emptyDir": {"sizeLimit": "256Mi"}}
        if sandbox else
        {"name": "service-data", "persistentVolumeClaim": {"claimName": pvc_name}}
    )
    deployment = {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": name, "namespace": namespace, "labels": labels},
        "spec": {
            "replicas": 1, "revisionHistoryLimit": 2, "minReadySeconds": 3,
            "progressDeadlineSeconds": config.rollout_timeout_seconds,
            "strategy": {
                "type": "RollingUpdate",
                "rollingUpdate": {"maxUnavailable": 0, "maxSurge": 1},
            },
            "selector": {"matchLabels": selector},
            "template": {
                "metadata": {"labels": labels},
                "spec": {
                    "serviceAccountName": name,
                    "automountServiceAccountToken": False,
                    "enableServiceLinks": False,
                    "hostNetwork": False, "hostPID": False, "hostIPC": False,
                    "securityContext": {
                        "runAsNonRoot": True, "runAsUser": 65532,
                        "runAsGroup": 65532, "fsGroup": 65532,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "terminationGracePeriodSeconds": 10,
                    "containers": [{
                        "name": name, "image": image, "imagePullPolicy": "IfNotPresent",
                        "ports": [
                            {"name": "game", "containerPort": game_port, "protocol": "TCP"},
                            {"name": "management", "containerPort": management_port, "protocol": "TCP"},
                        ],
                        "env": [
                            {"name": "ATTACK_DEFENSE_MANAGEMENT_TOKEN", "valueFrom": {
                                "secretKeyRef": {"name": secret_name, "key": "management-token"},
                            }},
                            {"name": "SERVICE_DATA_DIR", "value": "/data"},
                        ],
                        "securityContext": {
                            "privileged": False, "runAsNonRoot": True,
                            "runAsUser": 65532, "runAsGroup": 65532,
                            "readOnlyRootFilesystem": True,
                            "allowPrivilegeEscalation": False,
                            "capabilities": {"drop": ["ALL"]},
                        },
                        "resources": {
                            "requests": {
                                "cpu": config.cpu_request, "memory": config.memory_request,
                            },
                            "limits": {
                                "cpu": config.cpu_limit, "memory": config.memory_limit,
                            },
                        },
                        "startupProbe": {
                            "httpGet": {"path": health_path, "port": "game"},
                            "failureThreshold": 30, "periodSeconds": 2,
                            "timeoutSeconds": 1,
                        },
                        "readinessProbe": {
                            "httpGet": {"path": health_path, "port": "game"},
                            "failureThreshold": 3, "periodSeconds": 3,
                            "timeoutSeconds": 1,
                        },
                        "livenessProbe": {
                            "httpGet": {"path": health_path, "port": "game"},
                            "failureThreshold": 3, "periodSeconds": 10,
                            "timeoutSeconds": 2,
                        },
                        "volumeMounts": [
                            {"name": "service-data", "mountPath": "/data"},
                            {"name": "tmp", "mountPath": "/tmp"},
                        ],
                    }],
                    "volumes": [
                        data_volume,
                        {"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "64Mi"}},
                    ],
                },
            },
        },
    }
    resources.extend([
        deployment,
        {
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": name, "namespace": namespace, "labels": labels},
            "spec": {
                "type": "ClusterIP", "selector": selector,
                "publishNotReadyAddresses": False,
                "ports": [
                    {"name": "game", "port": game_port, "targetPort": "game"},
                    {"name": "management", "port": management_port, "targetPort": "management"},
                ],
            },
        },
        {
            "apiVersion": "policy/v1", "kind": "PodDisruptionBudget",
            "metadata": {"name": name, "namespace": namespace},
            "spec": {"minAvailable": 1, "selector": {"matchLabels": selector}},
        },
    ])
    return resources


def validate_manifests(
    resources: list[dict[str, Any]], config: KubernetesRuntimeConfig,
    *, sandbox: bool,
) -> tuple[str, ...]:
    violations: list[str] = []
    if not resources or any(resource.get("kind") not in _ALLOWED_KINDS for resource in resources):
        violations.append("unexpected_resource_kind")
        return tuple(violations)
    namespaces = {
        resource.get("metadata", {}).get("namespace")
        for resource in resources if resource.get("kind") != "Namespace"
    }
    namespace_resources = [r for r in resources if r.get("kind") == "Namespace"]
    namespace_name = namespace_resources[0].get("metadata", {}).get("name") if len(namespace_resources) == 1 else None
    if not namespace_name or namespaces != {namespace_name}:
        violations.append("namespace_scope_invalid")
    labels = (namespace_resources[0].get("metadata", {}).get("labels", {}) if namespace_resources else {})
    if labels.get("pod-security.kubernetes.io/enforce") != "restricted":
        violations.append("restricted_pod_security_required")

    deployments = [r for r in resources if r.get("kind") == "Deployment"]
    if len(deployments) != 1:
        violations.append("single_deployment_required")
        return tuple(dict.fromkeys(violations))
    deployment = deployments[0]
    spec = deployment.get("spec", {})
    pod = spec.get("template", {}).get("spec", {})
    containers = pod.get("containers") or []
    if len(containers) != 1:
        violations.append("single_container_required")
        return tuple(dict.fromkeys(violations))
    container = containers[0]
    image = str(container.get("image", ""))
    if "@" not in image or not _DIGEST_RE.fullmatch(image.rsplit("@", 1)[-1]):
        violations.append("image_not_digest_pinned")
    elif image.split("/", 1)[0] != config.image_registry:
        violations.append("registry_not_allowed")
    pod_security = pod.get("securityContext", {})
    container_security = container.get("securityContext", {})
    if (
        not pod_security.get("runAsNonRoot")
        or pod_security.get("seccompProfile", {}).get("type") != "RuntimeDefault"
        or pod.get("hostNetwork") is not False
        or pod.get("hostPID") is not False
        or pod.get("hostIPC") is not False
        or pod.get("automountServiceAccountToken") is not False
    ):
        violations.append("pod_not_hardened")
    if (
        container_security.get("privileged") is not False
        or container_security.get("allowPrivilegeEscalation") is not False
        or container_security.get("readOnlyRootFilesystem") is not True
        or container_security.get("runAsNonRoot") is not True
        or container_security.get("capabilities", {}).get("drop") != ["ALL"]
    ):
        violations.append("container_not_hardened")
    if not container.get("readinessProbe") or not container.get("startupProbe"):
        violations.append("readiness_gate_missing")
    if not container.get("resources", {}).get("requests") or not container.get("resources", {}).get("limits"):
        violations.append("resource_limits_missing")
    strategy = spec.get("strategy", {}).get("rollingUpdate", {})
    if strategy.get("maxUnavailable") != 0 or strategy.get("maxSurge") != 1:
        violations.append("safe_rollout_strategy_required")
    for volume in pod.get("volumes", []):
        if "hostPath" in volume:
            violations.append("host_path_forbidden")
    for environment in container.get("env", []):
        if environment.get("name") == "ATTACK_DEFENSE_MANAGEMENT_TOKEN" and "value" in environment:
            violations.append("plaintext_management_secret_forbidden")

    services = [r for r in resources if r.get("kind") == "Service"]
    if len(services) != 1 or services[0].get("spec", {}).get("type") != "ClusterIP":
        violations.append("cluster_ip_service_required")
    secrets = [r for r in resources if r.get("kind") == "Secret"]
    if len(secrets) != 1 or secrets[0].get("immutable") is not True:
        violations.append("immutable_secret_required")
    if not any(r.get("kind") == "ResourceQuota" for r in resources):
        violations.append("resource_quota_required")
    if not any(r.get("kind") == "LimitRange" for r in resources):
        violations.append("limit_range_required")
    default_deny = [
        r for r in resources
        if r.get("kind") == "NetworkPolicy"
        and r.get("metadata", {}).get("name") == "default-deny-all"
    ]
    if (
        len(default_deny) != 1
        or default_deny[0].get("spec", {}).get("podSelector") != {}
        or set(default_deny[0].get("spec", {}).get("policyTypes", [])) != {"Ingress", "Egress"}
        or "ingress" in default_deny[0].get("spec", {})
        or "egress" in default_deny[0].get("spec", {})
    ):
        violations.append("default_deny_all_required")
    policy_names = {
        r.get("metadata", {}).get("name", "") for r in resources
        if r.get("kind") == "NetworkPolicy"
    }
    if not any(name.endswith("management-ingress") for name in policy_names):
        violations.append("management_ingress_policy_required")
    has_game_policy = any(name.endswith("game-ingress") for name in policy_names)
    if sandbox and has_game_policy:
        violations.append("sandbox_game_ingress_forbidden")
    if not sandbox and not has_game_policy:
        violations.append("game_ingress_policy_required")
    pvcs = [r for r in resources if r.get("kind") == "PersistentVolumeClaim"]
    if sandbox and pvcs:
        violations.append("sandbox_persistence_forbidden")
    if not sandbox:
        if len(pvcs) != 1:
            violations.append("team_service_pvc_required")
        elif (
            spec.get("strategy", {}).get("rollingUpdate", {}).get("maxSurge") == 1
            and "ReadWriteMany" not in pvcs[0].get("spec", {}).get("accessModes", [])
        ):
            violations.append("rwx_required_for_surge_rollout")
    return tuple(dict.fromkeys(violations))


CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


def _subprocess_runner(
    command: list[str], *, input_text: str | None, timeout: int,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command, input=input_text, capture_output=True, text=True,
        timeout=timeout, check=False,
    )


class KubernetesRuntime:
    """Trusted host-side Kubernetes adapter.

    The Attack/Defense API never instantiates this class with cluster
    credentials. The CLI runner selects an explicit context, applies only the
    validated resource bundle over stdin, and waits for Deployment readiness.
    """

    def __init__(
        self, config: KubernetesRuntimeConfig,
        runner: CommandRunner = _subprocess_runner,
    ):
        config.validate()
        self.config = config
        self.runner = runner

    def _base_command(self) -> list[str]:
        command = [self.config.kubectl_binary]
        if self.config.kubeconfig:
            command.extend(("--kubeconfig", str(Path(self.config.kubeconfig).resolve())))
        if self.config.context:
            command.extend(("--context", self.config.context))
        return command

    def _run(
        self, arguments: list[str], *, input_text: str | None = None,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess[str] | None:
        try:
            return self.runner(
                [*self._base_command(), *arguments], input_text=input_text,
                timeout=timeout or self.config.rollout_timeout_seconds,
            )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            return None

    def _endpoints(self, instance: dict[str, Any]) -> tuple[str, str]:
        namespace = namespace_for(instance, self.config)
        name = deployment_name(instance)
        service_config = _service_config(instance)
        game_port = int(instance.get("internal_port") or instance.get("container_port") or 9000)
        management_port = int(service_config.get("management_port", 9001))
        host = f"{name}.{namespace}.svc"
        return f"http://{host}:{game_port}", f"http://{host}:{management_port}"

    def _result(
        self, instance: dict[str, Any], success: bool, image: str | None,
        error_code: str | None = None,
    ) -> RuntimeResult:
        endpoint, management = self._endpoints(instance)
        digest = image.rsplit("@", 1)[-1] if image and "@" in image else image
        runtime_id = (
            f"{namespace_for(instance, self.config)}:"
            f"{deployment_name(instance)}"
        )
        return RuntimeResult(
            success, runtime_id,
            endpoint, digest, error_code, management,
        )

    def _apply_bundle(
        self, instance: dict[str, Any], image_reference: str | None,
    ) -> RuntimeResult:
        try:
            resources = build_manifests(instance, self.config, image_reference)
        except ValueError:
            return self._result(instance, False, image_reference, "manifest_invalid")
        violations = validate_manifests(
            resources, self.config, sandbox=bool(instance.get("sandbox"))
        )
        if violations:
            return self._result(instance, False, image_reference, "manifest_policy_violation")
        image = next(
            resource for resource in resources if resource["kind"] == "Deployment"
        )["spec"]["template"]["spec"]["containers"][0]["image"]
        if self.config.dry_run:
            return self._result(instance, True, image)

        namespace_resource = next(r for r in resources if r["kind"] == "Namespace")
        namespaced = [r for r in resources if r["kind"] != "Namespace"]
        apply_args = [
            "apply", "--server-side", f"--field-manager={self.config.field_manager}",
            "-f", "-",
        ]
        if self.config.manage_namespaces:
            applied_namespace = self._run(
                apply_args, input_text=json.dumps(namespace_resource, separators=(",", ":"))
            )
            if applied_namespace is None or applied_namespace.returncode != 0:
                return self._result(instance, False, image, "namespace_apply_failed")
        applied = self._run(
            apply_args,
            input_text=json.dumps({
                "apiVersion": "v1", "kind": "List", "items": namespaced,
            }, separators=(",", ":")),
        )
        if applied is None or applied.returncode != 0:
            return self._result(instance, False, image, "resource_apply_failed")
        namespace = namespace_for(instance, self.config)
        name = deployment_name(instance)
        rollout = self._run([
            "rollout", "status", f"deployment/{name}", "--namespace", namespace,
            f"--timeout={self.config.rollout_timeout_seconds}s",
        ])
        if rollout is None:
            return self._result(instance, False, image, "runtime_timeout")
        if rollout.returncode != 0:
            return self._result(instance, False, image, "rollout_not_ready")
        return self._result(instance, True, image)

    def deploy(self, instance: dict) -> RuntimeResult:
        return self._apply_bundle(instance, None)

    def stop(self, instance: dict) -> RuntimeResult:
        if self.config.dry_run:
            return self._result(instance, True, instance.get("image_digest"))
        completed = self._run([
            "scale", f"deployment/{deployment_name(instance)}", "--replicas=0",
            "--namespace", namespace_for(instance, self.config),
        ])
        return self._result(
            instance, bool(completed and completed.returncode == 0),
            instance.get("image_digest"),
            None if completed and completed.returncode == 0 else "scale_failed",
        )

    def restart(self, instance: dict) -> RuntimeResult:
        if self.config.dry_run:
            return self._result(instance, True, instance.get("image_digest"))
        name = deployment_name(instance)
        namespace = namespace_for(instance, self.config)
        restarted = self._run([
            "rollout", "restart", f"deployment/{name}", "--namespace", namespace,
        ])
        if restarted is None or restarted.returncode != 0:
            return self._result(instance, False, instance.get("image_digest"), "restart_failed")
        rollout = self._run([
            "rollout", "status", f"deployment/{name}", "--namespace", namespace,
            f"--timeout={self.config.rollout_timeout_seconds}s",
        ])
        return self._result(
            instance, bool(rollout and rollout.returncode == 0),
            instance.get("image_digest"),
            None if rollout and rollout.returncode == 0 else "rollout_not_ready",
        )

    def inspect(self, instance: dict) -> RuntimeResult:
        if self.config.dry_run:
            return self._apply_bundle(instance, None)
        completed = self._run([
            "get", f"deployment/{deployment_name(instance)}", "--namespace",
            namespace_for(instance, self.config), "-o", "json",
        ])
        if completed is None or completed.returncode != 0:
            return self._result(instance, False, None, "inspect_failed")
        try:
            body = json.loads(completed.stdout)
            replicas = int(body.get("spec", {}).get("replicas", 0))
            status = body.get("status", {})
            ready = (
                replicas > 0
                and int(status.get("availableReplicas", 0)) >= replicas
                and int(status.get("updatedReplicas", 0)) >= replicas
                and int(status.get("observedGeneration", 0))
                >= int(body.get("metadata", {}).get("generation", 0))
            )
            image = body["spec"]["template"]["spec"]["containers"][0]["image"]
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return self._result(instance, False, None, "inspect_response_invalid")
        return self._result(instance, ready, image, None if ready else "deployment_not_ready")

    def replace_image(self, instance: dict, image_digest: str) -> RuntimeResult:
        return self._apply_bundle(instance, image_digest)

    def get_endpoint(self, instance: dict) -> str:
        return self._endpoints(instance)[0]

    def get_management_endpoint(self, instance: dict) -> str:
        return self._endpoints(instance)[1]
