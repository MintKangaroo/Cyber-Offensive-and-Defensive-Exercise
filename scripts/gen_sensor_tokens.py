#!/usr/bin/env python3
"""Derive scoped sensor credentials without distributing SERVICE_TOKEN to twins."""

from pathlib import Path
import hashlib
import hmac
import re
import sys

ASSETS = (
    "ground_station",
    "power_plant",
    "defense_network",
    "refinery_plant",
    "smart_factory",
    "water_utility",
    "lng_terminal",
    "railway_signaling",
    "airport_ot",
    "datacenter_bms",
    "hospital_ot",
)


def update(path: Path):
    source = path.read_text()
    values = dict(
        line.split("=", 1)
        for line in source.splitlines()
        if line and not line.startswith("#") and "=" in line
    )
    master = values.get("SERVICE_TOKEN", "").strip().strip("\"'")
    if not master:
        raise SystemExit("SERVICE_TOKEN is required before deriving sensor credentials")
    for asset in ASSETS:
        key = "RANGE_AGENT_" + asset.upper()
        value = hmac.new(
            master.encode(), ("range-agent-v1:" + asset).encode(), hashlib.sha256
        ).hexdigest()
        pattern = re.compile("^" + key + "=.*$", re.M)
        line = key + "=" + value
        source = (
            pattern.sub(line, source)
            if pattern.search(source)
            else source.rstrip() + "\n" + line + "\n"
        )
    path.write_text(source)
    path.chmod(0o600)
    print("  11 scoped sensor credentials synchronized (values withheld)")


if __name__ == "__main__":
    update(Path(sys.argv[1] if len(sys.argv) > 1 else ".env"))
