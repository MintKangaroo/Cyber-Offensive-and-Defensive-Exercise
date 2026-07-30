from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ContainerPolicySpec:
    privileged: bool = False
    network_mode: str = "bridge"
    pid_mode: str = ""
    ipc_mode: str = ""
    read_only_rootfs: bool = True
    cap_add: tuple[str, ...] = ()
    mounts: tuple[str, ...] = ()
    security_options: tuple[str, ...] = ("no-new-privileges:true",)


@dataclass(frozen=True)
class PolicyResult:
    allowed: bool
    violations: tuple[str, ...] = field(default_factory=tuple)


def validate_container_policy(spec: ContainerPolicySpec) -> PolicyResult:
    violations: list[str] = []
    if spec.privileged:
        violations.append("privileged_forbidden")
    if spec.network_mode == "host":
        violations.append("host_network_forbidden")
    if spec.pid_mode == "host":
        violations.append("host_pid_forbidden")
    if spec.ipc_mode == "host":
        violations.append("host_ipc_forbidden")
    if spec.cap_add:
        violations.append("capability_add_forbidden")
    for mount in spec.mounts:
        normalized = mount.lower()
        if normalized.startswith("/") or "docker.sock" in normalized:
            violations.append("host_mount_forbidden")
            break
    if "no-new-privileges:true" not in spec.security_options:
        violations.append("no_new_privileges_required")
    return PolicyResult(not violations, tuple(violations))
