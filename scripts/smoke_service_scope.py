#!/usr/bin/env python3
"""Isolated Docker contract drill: production settings, fresh secrets/data, no host ports.

Never touches the running training project. Only the generated project is removed.
Build/boot logs contain no service stdout (Auth's generated seed is not printed).
"""

from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVICES = (
    "auth",
    "config_service",
    "event_collector",
    "scoring_engine",
    "edr_backend",
    "incident",
    "injects",
    "ingest_proxy",
)


def run():
    project = "scope-drill-" + secrets.token_hex(4)
    with tempfile.TemporaryDirectory(prefix=project + "-") as temp:
        folder = Path(temp)
        envfile = folder / "scope.env"
        source = (ROOT / "docker-compose.yml").read_text() + (
            ROOT / "docker-compose.prod.yml"
        ).read_text()
        keys = set(re.findall(r"\$\{([A-Z_0-9]+):\?", source))
        values = {key: secrets.token_hex(32) for key in keys}
        values.update(
            AUTH_ADMIN_PASSWORD=secrets.token_hex(20),
            RANGE_ASSET_SCOPES=json.dumps(
                {
                    "ground_station": {
                        "team_id": "alpha",
                        "scenario_id": "scope-drill",
                    },
                    "power_plant": {"team_id": "bravo", "scenario_id": "scope-drill"},
                }
            ),
        )
        envfile.write_text("".join(k + "=" + v + "\n" for k, v in values.items()))
        envfile.chmod(0o600)
        config = subprocess.run(
            [
                "docker",
                "compose",
                "--env-file",
                str(envfile),
                "-f",
                "docker-compose.yml",
                "-f",
                "docker-compose.prod.yml",
                "config",
                "--format",
                "json",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        resolved = json.loads(config.stdout)
        drill = {"services": {}, "networks": {"scope": {"internal": True}}}
        for name in SERVICES:
            original = resolved["services"][name]
            env = original.get("environment", {})
            env["DATA_DIR"] = "/data"
            service = {
                "image": project + "-" + name
                if "build" in original
                else original["image"],
                "environment": env,
                "networks": {"scope": {"aliases": [name]}},
                "tmpfs": ["/data:rw,size=64m"],
                "mem_limit": "256m",
                "cpus": ".5",
            }
            if "build" in original:
                service["build"] = original["build"]
            if name == "ingest_proxy":
                service["volumes"] = original.get("volumes", [])
            if name == "auth":
                env["AUTH_ADMIN_PASSWORD"] = values["AUTH_ADMIN_PASSWORD"]
                env["SERVICE_TOKEN"] = values["SERVICE_TOKEN"]
            drill["services"][name] = service
        compose = folder / "compose.json"
        compose.write_text(json.dumps(drill))
        compose.chmod(0o600)
        command = ["docker", "compose", "-p", project, "-f", str(compose)]
        log = folder / "build.log"
        try:
            with log.open("w") as output:
                subprocess.run(
                    command + ["up", "-d", "--build"],
                    cwd=ROOT,
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    check=True,
                )
            print("Isolated production-profile services started", flush=True)
            script = (ROOT / "tests" / "integration" / "scope_drill.py").read_text()
            result = subprocess.run(
                command + ["exec", "-T", "auth", "python", "-"],
                input=script,
                text=True,
                capture_output=True,
            )
            if result.returncode:
                print(result.stdout)
                print(result.stderr)
                raise SystemExit("Service scope drill failed")
            print(result.stdout.strip())
        finally:
            subprocess.run(
                command + ["down", "--volumes", "--remove-orphans"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                ["docker", "image", "rm"]
                + [
                    project + "-" + name
                    for name in SERVICES
                    if "build" in resolved["services"][name]
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )


if __name__ == "__main__":
    run()
