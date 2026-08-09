from __future__ import annotations

import argparse
import json
import os
import socket
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv

from .config import AttackDefenseSettings
from .kubernetes_runtime import (
    KubernetesRuntime,
    KubernetesRuntimeConfig,
    map_image_registry,
)
from .service_fabric import DockerComposeRuntime, RuntimeResult

load_dotenv()


def _request(
    method: str, path: str, *, body: dict[str, Any] | None = None,
    participant: bool = False, headers: dict[str, str] | None = None,
) -> dict:
    base = os.environ.get("ATTACK_DEFENSE_API_URL", "http://localhost:8100").rstrip("/")
    token_name = "ATTACK_DEFENSE_COMPETITOR_TOKEN" if participant else "INSTRUCTOR_TOKEN"
    token = os.environ.get(token_name, "dev-instructor-token" if not participant else "")
    response = requests.request(
        method, base + path, json=body,
        headers={"Authorization": f"Bearer {token}", **(headers or {})}, timeout=30,
    )
    if response.status_code >= 400:
        raise SystemExit(f"{response.status_code}: {response.text}")
    return response.json()


def _print(value: Any) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False))


def _kubernetes_config(
    args: argparse.Namespace, settings: AttackDefenseSettings,
) -> KubernetesRuntimeConfig:
    kubeconfig_value = args.kubeconfig or settings.kubernetes_kubeconfig
    return KubernetesRuntimeConfig(
        allowed_registry=settings.allowed_registry,
        image_registry=settings.kubernetes_image_registry,
        management_master_token=settings.management_token,
        context=args.kube_context or settings.kubernetes_context,
        kubeconfig=Path(kubeconfig_value) if kubeconfig_value else None,
        kubectl_binary=args.kubectl or settings.kubernetes_kubectl,
        namespace_prefix=settings.kubernetes_namespace_prefix,
        field_manager=settings.kubernetes_field_manager,
        rollout_timeout_seconds=settings.kubernetes_rollout_timeout_seconds,
        pod_security_version=settings.kubernetes_pod_security_version,
        storage_class=settings.kubernetes_storage_class,
        storage_size=settings.kubernetes_storage_size,
        pvc_access_mode=settings.kubernetes_pvc_access_mode,
        cpu_request=settings.kubernetes_cpu_request,
        cpu_limit=settings.kubernetes_cpu_limit,
        memory_request=settings.kubernetes_memory_request,
        memory_limit=settings.kubernetes_memory_limit,
        manage_namespaces=settings.kubernetes_manage_namespaces,
        dry_run=not args.apply_kubernetes,
    )


def _runtime(args: argparse.Namespace):
    settings = AttackDefenseSettings.from_env()
    settings.validate()
    kind = args.runtime or settings.game_runtime
    if kind == "kubernetes":
        return kind, KubernetesRuntime(_kubernetes_config(args, settings)), settings
    return kind, DockerComposeRuntime(
        Path(args.compose_file), args.project, timeout_seconds=args.timeout
    ), settings


def _runtime_image(reference: str, kind: str, settings: AttackDefenseSettings) -> str:
    target = (
        settings.kubernetes_image_registry
        if kind == "kubernetes" else settings.runtime_registry
    )
    return map_image_registry(reference, settings.allowed_registry, target)


def _instance_for_runtime(
    instance: dict[str, Any], kind: str, settings: AttackDefenseSettings,
) -> dict[str, Any]:
    prepared = dict(instance)
    prepared["runtime_kind"] = kind
    prepared["management_secret_scope"] = "live"
    prepared["base_image"] = _runtime_image(
        str(prepared.get("base_image") or ""), kind, settings
    )
    return prepared


def _operator_services(match_id: str, headers: dict[str, str]) -> list[dict[str, Any]]:
    base = os.environ.get("ATTACK_DEFENSE_API_URL", "http://localhost:8100").rstrip("/")
    response = requests.get(
        f"{base}/api/attack-defense/operator/matches/{match_id}/services",
        headers=headers, timeout=30,
    )
    if response.status_code >= 400:
        raise SystemExit(f"{response.status_code}: {response.text}")
    return response.json().get("services", [])


def runtime_work(args: argparse.Namespace) -> None:
    base = os.environ.get("ATTACK_DEFENSE_API_URL", "http://localhost:8100").rstrip("/")
    token = os.environ.get("INSTRUCTOR_TOKEN", "dev-instructor-token")
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Runner-Id": args.runner_id or socket.gethostname(),
    }
    kind, runtime, settings = _runtime(args)
    if kind == "kubernetes" and not args.apply_kubernetes:
        raise SystemExit(
            "runtime-work requires --apply-kubernetes; no job was claimed"
        )
    claimed = requests.post(
        f"{base}/api/attack-defense/operator/runtime/jobs/claim",
        headers=headers, timeout=10,
    )
    if claimed.status_code >= 400:
        raise SystemExit(f"{claimed.status_code}: {claimed.text}")
    claimed = claimed.json().get("job")
    if not claimed:
        _print({"worked": False, "reason": "no_pending_job"})
        return
    payload = json.loads(claimed["payload"])
    claim_token = str(json.loads(claimed.get("result") or "{}").get(
        "claim_token", ""
    ))
    if not claim_token:
        raise SystemExit("claimed runtime job is missing its fencing token")
    runtime_id = payload.get("runtime_id", "")
    services = _operator_services(
        claimed["match_id"], {"Authorization": f"Bearer {token}"}
    )
    live_instance = next(
        (
            row for row in services
            if row["team_id"] == claimed["team_id"]
            and row["service_id"] == claimed["service_id"]
        ),
        None,
    )
    if live_instance is None:
        raise SystemExit("claimed runtime job has no service instance")
    instance = _instance_for_runtime(live_instance, kind, settings)
    operation = claimed["operation"]
    if operation == "sandbox_validate":
        instance.update({
            "sandbox": True,
            "runtime_id": runtime_id or f"sandbox-{payload['patch_id']}",
            "management_secret_scope": f"sandbox-{payload['patch_id']}",
        })
    if operation in {"sandbox_validate", "deploy"}:
        result = runtime.replace_image(
            instance, _runtime_image(payload["image_reference"], kind, settings)
        )
    elif operation in {"rollback", "rollback_instance"}:
        previous = str(payload.get("previous_image_digest") or "")
        if previous.startswith("sha256:"):
            repository = str(instance.get("base_image") or "").split("@", 1)[0]
            previous = f"{repository}@{previous}"
        result = runtime.replace_image(
            instance, _runtime_image(previous, kind, settings)
        )
    elif operation == "restart":
        result = runtime.restart(instance)
    else:
        result = RuntimeResult(
            False, runtime_id, error_code="unsupported_operation"
        )
    completed = requests.post(
        f"{base}/api/attack-defense/operator/runtime/jobs/{claimed['id']}/complete",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "success": result.success,
            "claim_token": claim_token,
            "result": {
                "runtime_id": result.runtime_id,
                "error_code": result.error_code,
                "image_digest": result.image_digest,
                "endpoint": result.endpoint,
                "management_endpoint": result.management_endpoint,
            },
        },
        timeout=240,
    )
    _print(completed.json())


def runtime_reconcile(args: argparse.Namespace) -> None:
    kind, runtime, settings = _runtime(args)
    token = os.environ.get("INSTRUCTOR_TOKEN", "dev-instructor-token")
    headers = {"Authorization": f"Bearer {token}"}
    services = _operator_services(args.match_id, headers)
    results: list[dict[str, Any]] = []
    apply_result = not (kind == "kubernetes" and not args.apply_kubernetes)
    for row in services:
        instance = _instance_for_runtime(row, kind, settings)
        result = runtime.deploy(instance)
        item = {
            "instance_id": row["id"], "team": row["team_slug"],
            "service": row["service_slug"], "success": result.success,
            "runtime_id": result.runtime_id, "endpoint": result.endpoint,
            "management_endpoint": result.management_endpoint,
            "image_digest": result.image_digest, "error_code": result.error_code,
            "recorded": False,
        }
        if apply_result:
            base = os.environ.get(
                "ATTACK_DEFENSE_API_URL", "http://localhost:8100"
            ).rstrip("/")
            response = requests.post(
                f"{base}/api/attack-defense/operator/matches/{args.match_id}"
                f"/instances/{row['id']}/runtime-result",
                headers=headers,
                json={
                    "success": result.success, "runtime_id": result.runtime_id,
                    "endpoint": result.endpoint,
                    "management_endpoint": result.management_endpoint,
                    "image_digest": result.image_digest,
                    "error_code": result.error_code,
                    "reason": args.reason,
                },
                timeout=30,
            )
            if response.status_code >= 400:
                item["record_error"] = f"{response.status_code}: {response.text}"
            else:
                item["recorded"] = True
        results.append(item)
        if args.fail_fast and not result.success:
            break
    _print({
        "runtime": kind, "dry_run": not apply_result,
        "match_id": args.match_id, "results": results,
    })


def capture_upload(args: argparse.Namespace) -> None:
    source = Path(args.file)
    if not source.is_file():
        raise SystemExit(f"capture file not found: {source}")
    base = os.environ.get("ATTACK_DEFENSE_API_URL", "http://localhost:8100").rstrip("/")
    token = os.environ.get("INSTRUCTOR_TOKEN", "dev-instructor-token")
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/vnd.tcpdump.pcap",
        "X-Operation-Reason": args.reason,
    }
    if args.round_id:
        headers["X-Round-Id"] = args.round_id
    if args.service_id:
        headers["X-Service-Id"] = args.service_id
    with source.open("rb") as handle:
        response = requests.post(
            f"{base}/api/attack-defense/operator/matches/{args.match_id}/captures",
            headers=headers, data=handle, timeout=args.timeout,
        )
    if response.status_code >= 400:
        raise SystemExit(f"{response.status_code}: {response.text}")
    _print(response.json())


def capture_download(args: argparse.Namespace) -> None:
    target = Path(args.output)
    if target.exists() and not args.force:
        raise SystemExit(f"output exists (use --force to replace): {target}")
    base = os.environ.get("ATTACK_DEFENSE_API_URL", "http://localhost:8100").rstrip("/")
    token = os.environ.get("ATTACK_DEFENSE_COMPETITOR_TOKEN", "")
    if not token:
        raise SystemExit("ATTACK_DEFENSE_COMPETITOR_TOKEN is required")
    response = requests.get(
        f"{base}/api/attack-defense/matches/{args.match_id}/captures/"
        f"{args.capture_id}/download",
        headers={"Authorization": f"Bearer {token}"}, timeout=args.timeout,
    )
    if response.status_code >= 400:
        raise SystemExit(f"{response.status_code}: {response.text}")
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    try:
        temporary.write_bytes(response.content)
        temporary.replace(target)
    finally:
        if temporary.exists():
            temporary.unlink()
    _print({
        "downloaded": True, "output": str(target),
        "sha256": response.headers.get("X-Capture-SHA256"),
        "watermark": response.headers.get("X-Capture-Watermark"),
    })


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="cyber-range")
    ad = root.add_subparsers(dest="area", required=True).add_parser("ad")
    commands = ad.add_subparsers(dest="command", required=True)

    create = commands.add_parser("match-create")
    create.add_argument("--id")
    create.add_argument("--name", required=True)
    create.add_argument("--mode", choices=["attack_defense", "hybrid_live_fire"],
                        default="attack_defense")

    for command in ("match-start", "match-pause", "match-resume", "match-end"):
        item = commands.add_parser(command)
        item.add_argument("match_id")
        item.add_argument("--reason", default=f"CLI {command}")

    status = commands.add_parser("round-status")
    status.add_argument("match_id")
    finalize = commands.add_parser("round-finalize")
    finalize.add_argument("match_id")
    services = commands.add_parser("service-list")
    services.add_argument("match_id")

    submit = commands.add_parser("flag-submit")
    submit.add_argument("match_id")
    submit.add_argument("flag")

    patch = commands.add_parser("patch-status")
    patch.add_argument("match_id")
    patch.add_argument("patch_id")

    score = commands.add_parser("score-recalculate")
    score.add_argument("match_id")

    commands.add_parser("ha-status")

    koth_config = commands.add_parser("koth-configure")
    koth_config.add_argument("match_id")
    koth_config.add_argument("--disable", action="store_true")
    koth_config.add_argument("--service-id", action="append", default=[])
    koth_config.add_argument("--lease-rounds", type=int)
    koth_config.add_argument("--points-per-round", type=int)
    koth_config.add_argument("--score-weight", type=float, default=1.0)
    koth_config.add_argument("--reason", required=True)

    koth_status = commands.add_parser("koth-status")
    koth_status.add_argument("match_id")

    stealth_config = commands.add_parser("stealth-configure")
    stealth_config.add_argument("match_id")
    stealth_config.add_argument("--disable", action="store_true")
    stealth_config.add_argument("--alert-delay-rounds", type=int)
    stealth_config.add_argument("--detection-window-rounds", type=int)
    stealth_config.add_argument("--attacker-points", type=int)
    stealth_config.add_argument("--defender-points", type=int)
    stealth_config.add_argument("--attack-score-weight", type=float, default=1.0)
    stealth_config.add_argument("--detection-score-weight", type=float, default=1.0)
    stealth_config.add_argument("--reason", required=True)

    stealth_status = commands.add_parser("stealth-status")
    stealth_status.add_argument("match_id")

    detection = commands.add_parser("stealth-detection-report")
    detection.add_argument("match_id")
    detection.add_argument("service_id")
    detection.add_argument("indicator_hash")
    detection.add_argument("evidence_summary")
    detection.add_argument("--idempotency-key", required=True)

    capture = commands.add_parser("capture-upload")
    capture.add_argument("match_id")
    capture.add_argument("file")
    capture.add_argument("--round-id")
    capture.add_argument("--service-id")
    capture.add_argument("--reason", required=True)
    capture.add_argument("--timeout", type=int, default=180)

    capture_list = commands.add_parser("capture-list")
    capture_list.add_argument("match_id")

    capture_get = commands.add_parser("capture-download")
    capture_get.add_argument("match_id")
    capture_get.add_argument("capture_id")
    capture_get.add_argument("output")
    capture_get.add_argument("--force", action="store_true")
    capture_get.add_argument("--timeout", type=int, default=60)

    demo = commands.add_parser("demo-bootstrap")
    demo.add_argument("--no-start", action="store_true")

    work = commands.add_parser("runtime-work")
    work.add_argument("--runner-id")

    reconcile = commands.add_parser("runtime-reconcile")
    reconcile.add_argument("match_id")
    reconcile.add_argument("--reason", default="CLI runtime reconciliation")
    reconcile.add_argument("--fail-fast", action="store_true")

    for item in (work, reconcile):
        item.add_argument(
            "--runtime", choices=["docker_compose", "kubernetes"]
        )
        item.add_argument("--compose-file", default="docker-compose.yml")
        item.add_argument("--project", default="cyber-range-platform")
        item.add_argument("--timeout", type=int, default=180)
        item.add_argument("--kube-context")
        item.add_argument("--kubeconfig")
        item.add_argument("--kubectl")
        item.add_argument(
            "--apply-kubernetes", action="store_true",
            help="apply validated manifests to the explicitly selected context",
        )
    return root


def main(argv: list[str] | None = None) -> None:
    args = parser().parse_args(argv)
    command = args.command
    if command == "match-create":
        _print(_request("POST", "/api/attack-defense/matches", body={
            "id": args.id, "name": args.name, "mode": args.mode,
        }))
    elif command.startswith("match-"):
        action = command.removeprefix("match-")
        _print(_request(
            "POST", f"/api/attack-defense/matches/{args.match_id}/{action}",
            body={"reason": args.reason},
        ))
    elif command == "round-status":
        _print(_request(
            "GET", f"/api/attack-defense/matches/{args.match_id}/rounds/current"
        ))
    elif command == "round-finalize":
        _print(_request(
            "POST",
            f"/api/attack-defense/matches/{args.match_id}/rounds/current/finalize",
        ))
    elif command == "service-list":
        _print(_request(
            "GET", f"/api/attack-defense/operator/matches/{args.match_id}/services"
        ))
    elif command == "flag-submit":
        _print(_request(
            "POST", f"/api/attack-defense/matches/{args.match_id}/flags/submit",
            body={"flag": args.flag}, participant=True,
        ))
    elif command == "patch-status":
        _print(_request(
            "GET", f"/api/attack-defense/matches/{args.match_id}/patches/{args.patch_id}",
            participant=True,
        ))
    elif command == "score-recalculate":
        _print(_request(
            "POST", f"/api/attack-defense/matches/{args.match_id}/score/recalculate"
        ))
    elif command == "ha-status":
        _print(_request("GET", "/api/attack-defense/operator/ha/status"))
    elif command == "koth-configure":
        body: dict[str, Any] = {
            "enabled": not args.disable,
            "service_ids": args.service_id,
            "score_weight": args.score_weight,
            "reason": args.reason,
        }
        if args.lease_rounds is not None:
            body["lease_rounds"] = args.lease_rounds
        if args.points_per_round is not None:
            body["points_per_round"] = args.points_per_round
        _print(_request(
            "POST",
            f"/api/attack-defense/operator/matches/{args.match_id}/koth/configure",
            body=body,
        ))
    elif command == "koth-status":
        _print(_request(
            "GET", f"/api/attack-defense/operator/matches/{args.match_id}/koth"
        ))
    elif command == "stealth-configure":
        body = {
            "enabled": not args.disable,
            "attack_score_weight": args.attack_score_weight,
            "detection_score_weight": args.detection_score_weight,
            "reason": args.reason,
        }
        optional = {
            "alert_delay_rounds": args.alert_delay_rounds,
            "detection_window_rounds": args.detection_window_rounds,
            "attacker_undetected_points": args.attacker_points,
            "defender_detection_points": args.defender_points,
        }
        body.update({key: value for key, value in optional.items() if value is not None})
        _print(_request(
            "POST",
            f"/api/attack-defense/operator/matches/{args.match_id}/stealth/configure",
            body=body,
        ))
    elif command == "stealth-status":
        _print(_request(
            "GET", f"/api/attack-defense/operator/matches/{args.match_id}/stealth"
        ))
    elif command == "stealth-detection-report":
        _print(_request(
            "POST",
            f"/api/attack-defense/matches/{args.match_id}/stealth/detections",
            body={
                "service_id": args.service_id,
                "indicator_hash": args.indicator_hash,
                "evidence_summary": args.evidence_summary,
            },
            participant=True,
            headers={"Idempotency-Key": args.idempotency_key},
        ))
    elif command == "capture-upload":
        capture_upload(args)
    elif command == "capture-list":
        _print(_request(
            "GET", f"/api/attack-defense/operator/matches/{args.match_id}/captures"
        ))
    elif command == "capture-download":
        capture_download(args)
    elif command == "demo-bootstrap":
        from scripts.bootstrap_attack_defense_demo import bootstrap
        _print(bootstrap(start=not args.no_start))
    elif command == "runtime-work":
        runtime_work(args)
    elif command == "runtime-reconcile":
        runtime_reconcile(args)


if __name__ == "__main__":
    main()
