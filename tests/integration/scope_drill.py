"""Runs inside scripts/smoke_service_scope.py's isolated Auth container."""

import json
import os
import time
import uuid
import jwt
import requests
from shared.service_auth import range_agent_signature

PORTS = {
    "auth": 8051,
    "config_service": 8030,
    "event_collector": 8010,
    "scoring_engine": 8020,
    "edr_backend": 8080,
    "incident": 8095,
    "injects": 8096,
    "ingest_proxy": 8010,
}
checks = 0


def call(service, path, method="GET", token="", body=None, expected=200, raw_auth=""):
    global checks
    r = requests.request(
        method,
        f"http://{service}:{PORTS[service]}{path}",
        headers={"Authorization": raw_auth or ("Bearer " + token if token else "")},
        json=body,
        timeout=10,
    )
    assert r.status_code == expected, (
        f"{service}{path}: expected {expected}, got {r.status_code}"
    )
    checks += 1
    return r.json() if r.content else {}


for service, port in PORTS.items():
    for attempt in range(40):
        try:
            if requests.get(f"http://{service}:{port}/health", timeout=2).ok:
                break
        except requests.RequestException:
            pass
        time.sleep(0.5)
    else:
        raise RuntimeError(f"{service} did not become healthy")

admin = call(
    "auth",
    "/auth/login",
    "POST",
    body={"username": "instructor", "password": os.environ["AUTH_ADMIN_PASSWORD"]},
)["access_token"]
users = {}
for role, team in [
    ("blue", "alpha"),
    ("blue", "bravo"),
    ("red", "alpha"),
    ("observer", ""),
]:
    name = role + team
    pw = uuid.uuid4().hex
    call(
        "auth",
        "/auth/register",
        "POST",
        admin,
        {
            "username": name,
            "password": pw,
            "role": role,
            "team_id": team,
            "match_id": "scope-drill",
        },
    )
    users[name] = call(
        "auth", "/auth/login", "POST", body={"username": name, "password": pw}
    )["access_token"]

call("event_collector", "/events", expected=401)
call("edr_backend", "/edr/hosts", token=users["redalpha"], expected=403)
master = os.environ["SERVICE_TOKEN"]
for asset in ("ground_station", "power_plant"):
    agent = "RangeAgent " + asset + ":" + range_agent_signature(master, asset)
    call("config_service", "/config/patches?asset=" + asset, raw_auth=agent)
    call("config_service", "/instructor/audit", raw_auth=agent, expected=403)
    call(
        "edr_backend",
        "/edr/ingest",
        "POST",
        raw_auth=agent,
        body={"asset": asset, "timestamp": time.time(), "processes": []},
    )
    call(
        "event_collector",
        "/events",
        "POST",
        raw_auth=agent,
        body={
            "event_id": str(uuid.uuid4()),
            "event_type": "asset_compromised",
            "timestamp": time.time() - 60,
            "actor": "red",
            "target_asset": asset,
            "team_id": "forged",
            "scenario_id": "forged",
        },
    )
agent = "RangeAgent ground_station:" + range_agent_signature(master, "ground_station")
call(
    "ingest_proxy",
    "/events",
    "POST",
    raw_auth=agent,
    body={
        "event_id": str(uuid.uuid4()),
        "event_type": "red_attack_started",
        "actor": "red",
        "target_asset": "ground_station",
    },
)
call(
    "ingest_proxy",
    "/events",
    "POST",
    body={
        "event_id": "unauthenticated",
        "event_type": "red_attack_started",
        "actor": "red",
        "target_asset": "ground_station",
    },
    expected=401,
)
blue = users["bluealpha"]
hosts = call("edr_backend", "/edr/hosts", token=blue)["hosts"]
assert [h["asset"] for h in hosts] == ["ground_station"]
events = call("event_collector", "/events", token=blue)["events"]
assert (
    len(events) == 2
    and events[0]["team_id"] == "alpha"
    and events[0]["scenario_id"] == "scope-drill"
)
call(
    "edr_backend",
    "/edr/hosts/power_plant/isolate",
    "POST",
    blue,
    {"reason": "forged isolation"},
    expected=404,
)
call(
    "edr_backend",
    "/edr/hosts/ground_station/isolate",
    "POST",
    blue,
    {"reason": "scope drill containment"},
)
assert (
    call("config_service", "/config/quarantine?asset=ground_station", token=admin)[
        "quarantined"
    ]
    is True
)
incident = call(
    "incident",
    "/incidents/from-alert",
    "POST",
    admin,
    {
        "alert_id": "drill-evidence",
        "title": "Scoped incident",
        "host": "ground_station",
        "team_id": "alpha",
        "scenario_id": "scope-drill",
    },
)["id"]
call("incident", "/incidents/" + incident, token=users["bluebravo"], expected=404)
call(
    "incident",
    "/incidents/" + incident + "/note",
    "POST",
    blue,
    {"note": "Verified evidence in isolated drill"},
)
call(
    "config_service",
    "/instructor/killswitch",
    "POST",
    admin,
    {"reason": "missing confirmation"},
    expected=400,
)
call(
    "config_service",
    "/instructor/killswitch",
    "POST",
    admin,
    {"confirm": True, "reason": "isolated drill safety check"},
)
assert call("config_service", "/config/killswitch", token=admin)["killswitch"] is True
jti = jwt.decode(blue, options={"verify_signature": False})["jti"]
call("auth", "/auth/revoke", "POST", admin, {"jti": jti})
call("edr_backend", "/edr/hosts", token=blue, expected=401)
call("event_collector", "/events", token=blue, expected=401)
print(
    f"{checks} real HTTP checks passed: scoped sensors, Auth revocation, own-team EDR/incident, confirmed safety; isolated fixture data only."
)
