from __future__ import annotations

import argparse
import json
import os
import socket
import sys
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv

from .service_fabric import DockerComposeRuntime


load_dotenv()


def _request(
    method: str, path: str, *, body: dict[str, Any] | None = None,
    participant: bool = False,
) -> dict:
    base = os.environ.get("ATTACK_DEFENSE_API_URL", "http://localhost:8100").rstrip("/")
    token_name = "ATTACK_DEFENSE_COMPETITOR_TOKEN" if participant else "INSTRUCTOR_TOKEN"
    token = os.environ.get(token_name, "dev-instructor-token" if not participant else "")
    response = requests.request(
        method, base + path, json=body,
        headers={"Authorization": f"Bearer {token}"}, timeout=30,
    )
    if response.status_code >= 400:
        raise SystemExit(f"{response.status_code}: {response.text}")
    return response.json()


def _print(value: Any) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False))


def runtime_work(args: argparse.Namespace) -> None:
    base = os.environ.get("ATTACK_DEFENSE_API_URL", "http://localhost:8100").rstrip("/")
    token = os.environ.get("INSTRUCTOR_TOKEN", "dev-instructor-token")
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Runner-Id": args.runner_id or socket.gethostname(),
    }
    claimed = requests.post(
        f"{base}/api/attack-defense/operator/runtime/jobs/claim",
        headers=headers, timeout=10,
    ).json().get("job")
    if not claimed:
        _print({"worked": False, "reason": "no_pending_job"})
        return
    payload = json.loads(claimed["payload"])
    control_registry = os.environ.get(
        "PATCH_ALLOWED_REGISTRY", "registry.local:5000"
    ).rstrip("/")
    runtime_registry = os.environ.get(
        "PATCH_RUNTIME_REGISTRY", "localhost:5000"
    ).rstrip("/")

    def runtime_reference(reference: str | None) -> str:
        if not reference:
            return ""
        prefix = f"{control_registry}/"
        if reference.startswith(prefix):
            return f"{runtime_registry}/{reference[len(prefix):]}"
        return reference

    runtime_id = payload.get("runtime_id", "")
    runtime = DockerComposeRuntime(
        Path(args.compose_file), args.project, timeout_seconds=args.timeout
    )
    instance = {"runtime_id": runtime_id, "id": claimed.get("instance_id") or runtime_id}
    operation = claimed["operation"]
    if operation in {"sandbox_validate", "deploy"}:
        result = runtime.replace_image(
            instance, runtime_reference(payload["image_reference"])
        )
    elif operation in {"rollback", "rollback_instance"}:
        result = runtime.replace_image(
            instance, runtime_reference(payload["previous_image_digest"])
        )
    elif operation == "restart":
        result = runtime.restart(instance)
    else:
        result = type("Unknown", (), {
            "success": False, "error_code": "unsupported_operation",
            "runtime_id": runtime_id, "image_digest": None,
        })()
    completed = requests.post(
        f"{base}/api/attack-defense/operator/runtime/jobs/{claimed['id']}/complete",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "success": result.success,
            "result": {
                "runtime_id": result.runtime_id,
                "error_code": result.error_code,
                "image_digest": result.image_digest,
            },
        },
        timeout=240,
    )
    _print(completed.json())


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

    demo = commands.add_parser("demo-bootstrap")
    demo.add_argument("--no-start", action="store_true")

    work = commands.add_parser("runtime-work")
    work.add_argument("--compose-file", default="docker-compose.yml")
    work.add_argument("--project", default="cyber-range-platform")
    work.add_argument("--timeout", type=int, default=180)
    work.add_argument("--runner-id")
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
    elif command == "demo-bootstrap":
        from scripts.bootstrap_attack_defense_demo import bootstrap
        _print(bootstrap(start=not args.no_start))
    elif command == "runtime-work":
        runtime_work(args)


if __name__ == "__main__":
    main()
