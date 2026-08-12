from __future__ import annotations

import os
import subprocess
import time
from typing import Any

import requests
from dotenv import load_dotenv


load_dotenv()
AD_API = os.environ.get("ATTACK_DEFENSE_API_URL", "http://localhost:8100").rstrip("/")
AUTH_API = os.environ.get("AUTH_API_URL", "http://localhost:8051").rstrip("/")
OPERATOR_TOKEN = os.environ.get("INSTRUCTOR_TOKEN", "dev-instructor-token")
MATCH_ID = os.environ.get("ATTACK_DEFENSE_DEMO_MATCH_ID", "ad-demo")


def wait_until_ready(timeout_seconds: int = 90) -> None:
    deadline = time.monotonic() + timeout_seconds
    pending = {
        "Attack/Defense API": f"{AD_API}/ready",
        "Auth API": f"{AUTH_API}/health",
    }
    last_errors: dict[str, str] = {}
    while pending and time.monotonic() < deadline:
        for name, url in list(pending.items()):
            try:
                response = requests.get(url, timeout=2)
                if response.status_code == 200:
                    pending.pop(name)
                    last_errors.pop(name, None)
                else:
                    last_errors[name] = f"HTTP {response.status_code}"
            except requests.RequestException as exc:
                last_errors[name] = type(exc).__name__
        if pending:
            time.sleep(1)
    if pending:
        detail = ", ".join(
            f"{name} ({last_errors.get(name, 'not ready')})" for name in pending
        )
        raise RuntimeError(f"demo dependencies did not become ready: {detail}")


def call(method: str, path: str, body: dict[str, Any] | None = None) -> dict:
    response = requests.request(
        method, AD_API + path, json=body,
        headers={"Authorization": f"Bearer {OPERATOR_TOKEN}"}, timeout=60,
    )
    if response.status_code == 409:
        return {"existing": True}
    response.raise_for_status()
    return response.json()


def bootstrap(start: bool = True) -> dict:
    wait_until_ready()
    call("POST", "/api/attack-defense/matches", {
        "id": MATCH_ID, "name": "Operation Blackout",
        "mode": "attack_defense", "round_duration_seconds": 60,
        "active_flag_window": 3,
        "config": {"scoreboard_delay_rounds": 0},
    })
    teams = [
        ("team-1", "team-01", "Team 01"),
        ("team-2", "team-02", "Team 02"),
        ("team-3", "team-03", "Team 03"),
    ]
    for team_id, slug, name in teams:
        call("POST", f"/api/attack-defense/matches/{MATCH_ID}/teams", {
            "id": team_id, "slug": slug, "name": name,
        })
    endpoint_notes = {
        "team-01": "http://ad_team_01_notes:9000",
        "team-02": "http://ad_team_02_notes:9000",
        "team-03": "http://ad_team_03_notes:9000",
    }
    endpoint_vault = {
        "team-01": "http://ad_team_01_vault:9000",
        "team-02": "http://ad_team_02_vault:9000",
        "team-03": "http://ad_team_03_vault:9000",
    }
    management_notes = {k: v.replace(":9000", ":9001") for k, v in endpoint_notes.items()}
    management_vault = {k: v.replace(":9000", ":9001") for k, v in endpoint_vault.items()}
    call("POST", f"/api/attack-defense/matches/{MATCH_ID}/services", {
        "id": "service-vulnerable-notes", "slug": "vulnerable-notes",
        "name": "Vulnerable Notes", "base_image": "cyber-range/ad-vulnerable-notes:base",
        "base_image_digest": _local_image_digest(
            "cyber-range/ad-vulnerable-notes:base"
        ),
        "internal_port": 9000, "checker_type": "vulnerable_notes",
        "config": {
            "endpoint_by_team": endpoint_notes,
            "management_endpoint_by_team": management_notes,
            "runtime_id_by_team": {
                "team-01": "ad_team_01_notes", "team-02": "ad_team_02_notes",
                "team-03": "ad_team_03_notes",
            },
        },
    })
    call("POST", f"/api/attack-defense/matches/{MATCH_ID}/services", {
        "id": "service-file-vault", "slug": "file-vault",
        "name": "File Vault", "base_image": "cyber-range/ad-file-vault:base",
        "base_image_digest": _local_image_digest(
            "cyber-range/ad-file-vault:base"
        ),
        "internal_port": 9000, "checker_type": "file_vault",
        "config": {
            "endpoint_by_team": endpoint_vault,
            "management_endpoint_by_team": management_vault,
            "runtime_id_by_team": {
                "team-01": "ad_team_01_vault", "team-02": "ad_team_02_vault",
                "team-03": "ad_team_03_vault",
            },
        },
    })
    accounts = _bootstrap_accounts(teams)
    matches = call("GET", "/api/attack-defense/operator/matches").get(
        "matches", []
    )
    current = next(
        (item for item in matches if item.get("id") == MATCH_ID), None
    )
    match = (
        call(
            "POST", f"/api/attack-defense/matches/{MATCH_ID}/start",
            {"reason": "local demo bootstrap"},
        )
        if start and current and current.get("status") == "draft"
        else (current or {"status": "draft"})
    )
    return {
        "match_id": MATCH_ID, "match": match, "accounts": accounts,
        "service_ports": {
            "team-01": {"notes": 9101, "vault": 9201},
            "team-02": {"notes": 9102, "vault": 9202},
            "team-03": {"notes": 9103, "vault": 9203},
        },
    }


def _local_image_digest(image: str) -> str | None:
    """Resolve an immutable local base ID without exposing a Docker socket."""
    try:
        result = subprocess.run(
            ["docker", "image", "inspect", "--format={{.Id}}", image],
            check=True, capture_output=True, text=True, timeout=5,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return None
    digest = result.stdout.strip()
    return digest if digest.startswith("sha256:") and len(digest) == 71 else None


def _bootstrap_accounts(teams: list[tuple[str, str, str]]) -> list[dict]:
    admin_password = os.environ.get("AUTH_ADMIN_PASSWORD", "demo-operator-change-me")
    login = requests.post(
        f"{AUTH_API}/auth/login",
        json={"username": "instructor", "password": admin_password}, timeout=10,
    )
    if login.status_code != 200:
        return [{"warning": "auth service unavailable or admin password differs"}]
    auth = {"Authorization": f"Bearer {login.json()['access_token']}"}
    accounts = []
    for index, (team_id, _, _) in enumerate(teams, 1):
        username = f"team{index:02}"
        password = f"demo-team-{index:02}-change-me"
        response = requests.post(
            f"{AUTH_API}/auth/register", headers=auth,
            json={
                "username": username, "password": password, "role": "competitor",
                "team_id": team_id, "match_id": MATCH_ID,
            },
            timeout=10,
        )
        if response.status_code < 400:
            accounts.append({"username": username, "password": password, "team_id": team_id})
    return accounts


if __name__ == "__main__":
    import json
    print(json.dumps(bootstrap(), indent=2, ensure_ascii=False))
