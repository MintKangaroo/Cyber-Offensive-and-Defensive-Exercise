from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_DIR = ROOT / ".runtime" / "training"
STATE_PATH = RUNTIME_DIR / "processes.json"

DASHBOARDS = (
    {
        "name": "START HERE", "slug": "start", "port": 5179,
        "cwd": ROOT / "dashboards" / "start-here",
        "serve_dir": ".",
    },
    {
        "name": "EDR Console", "slug": "edr", "port": 5173,
        "cwd": ROOT / "services" / "edr" / "console",
        "build_command": ["npm", "run", "build"], "serve_dir": "dist",
    },
    {
        "name": "Live Fire", "slug": "livefire", "port": 5178,
        "cwd": ROOT / "dashboards" / "livefire",
        "build_command": ["npm", "run", "build"], "serve_dir": "dist",
    },
    {
        "name": "SIEM Console", "slug": "siem", "port": 5175,
        "cwd": ROOT / "dashboards" / "siem",
        "build_command": ["npm", "run", "build"], "serve_dir": "dist",
    },
    {
        "name": "Red Portal", "slug": "red", "port": 5176,
        "cwd": ROOT / "dashboards" / "redportal",
        "build_command": ["npm", "run", "build"], "serve_dir": "dist",
    },
    {
        "name": "Blue Portal", "slug": "blue", "port": 5177,
        "cwd": ROOT / "dashboards" / "blueportal",
        "build_command": ["npm", "run", "build"], "serve_dir": "dist",
    },
    {
        "name": "Control Tower", "slug": "control", "port": 5180,
        "cwd": ROOT / "dashboards" / "control-tower",
        "serve_dir": ".",
    },
)

A_D_BUILD_SERVICES = (
    "attack_defense", "ad_team_01_notes", "ad_team_01_vault",
)


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=ROOT, check=check, text=True)


def read_state() -> list[dict]:
    try:
        value = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        return value if isinstance(value, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def write_state(processes: list[dict]) -> None:
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    temporary = STATE_PATH.with_suffix(".tmp")
    temporary.write_text(json.dumps(processes, indent=2), encoding="utf-8")
    temporary.replace(STATE_PATH)


def process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
        return True
    except (OSError, ValueError):
        return False


def is_managed_process(pid: int) -> bool:
    proc = Path("/proc") / str(pid)
    try:
        cwd = (proc / "cwd").resolve(strict=True)
        command = (proc / "cmdline").read_bytes().replace(b"\0", b" ").decode(
            "utf-8", errors="replace",
        )
    except OSError:
        return False
    allowed_roots = {item["cwd"].resolve() for item in DASHBOARDS}
    return cwd in allowed_roots and any(
        marker in command for marker in ("vite", "npm run dev", "http.server")
    )


def managed_process_groups() -> set[int]:
    pids = {
        int(item["pid"]) for item in read_state()
        if str(item.get("pid", "")).isdigit()
    }
    for entry in Path("/proc").iterdir():
        if entry.name.isdigit() and is_managed_process(int(entry.name)):
            pids.add(int(entry.name))
    groups: set[int] = set()
    for pid in pids:
        if is_managed_process(pid):
            try:
                groups.add(os.getpgid(pid))
            except ProcessLookupError:
                pass
    return groups


def stop_dashboards() -> None:
    groups = managed_process_groups()
    for process_group in groups:
        try:
            os.killpg(process_group, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 8
    while groups and time.monotonic() < deadline:
        groups = {
            process_group for process_group in groups
            if process_group_exists(process_group)
        }
        if groups:
            time.sleep(0.2)
    for process_group in groups:
        try:
            os.killpg(process_group, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        STATE_PATH.unlink()
    except FileNotFoundError:
        pass


def install_frontend_dependencies(item: dict) -> None:
    cwd = item["cwd"]
    if not item.get("build_command") or (cwd / "node_modules").is_dir():
        return
    command = ["npm", "ci"] if (cwd / "package-lock.json").exists() else ["npm", "install"]
    subprocess.run(command, cwd=cwd, check=True)


def prepare_dashboard(item: dict) -> Path:
    install_frontend_dependencies(item)
    if build_command := item.get("build_command"):
        subprocess.run(build_command, cwd=item["cwd"], check=True)
    serve_dir = (item["cwd"] / item["serve_dir"]).resolve()
    if not (serve_dir / "index.html").is_file():
        raise RuntimeError(f"dashboard build is missing {serve_dir / 'index.html'}")
    return serve_dir


def static_server_command(item: dict, serve_dir: Path) -> list[str]:
    return [
        sys.executable, "-m", "http.server", str(item["port"]),
        "--bind", "0.0.0.0", "--directory", str(serve_dir),
    ]


def start_dashboards() -> None:
    stop_dashboards()
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    serve_dirs = {
        item["slug"]: prepare_dashboard(item)
        for item in DASHBOARDS
    }
    processes: list[dict] = []
    for item in DASHBOARDS:
        log_path = RUNTIME_DIR / f"{item['slug']}.log"
        with log_path.open("wb") as output:
            child = subprocess.Popen(
                static_server_command(item, serve_dirs[item["slug"]]),
                cwd=item["cwd"], stdout=output,
                stderr=subprocess.STDOUT, start_new_session=True,
            )
        processes.append({
            "name": item["name"], "slug": item["slug"],
            "port": item["port"], "pid": child.pid,
            "cwd": str(item["cwd"]), "log": str(log_path),
        })
        write_state(processes)


def wait_for_url(url: str, timeout_seconds: int = 45) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error = "not reachable"
    while time.monotonic() < deadline:
        try:
            with urlopen(url, timeout=2) as response:
                if response.status < 500:
                    return
                last_error = f"HTTP {response.status}"
        except HTTPError as exc:
            if exc.code < 500:
                return
            last_error = f"HTTP {exc.code}"
        except (URLError, OSError) as exc:
            last_error = type(exc).__name__
        time.sleep(0.5)
    raise RuntimeError(f"{url} did not become ready ({last_error})")


def up() -> None:
    print("[training] preparing Attack/Defense images")
    if os.environ.get("TRAINING_SKIP_BUILD", "").lower() not in {"1", "true", "yes"}:
        run(["docker", "compose", "build", *A_D_BUILD_SERVICES])
    print("[training] starting all default Docker Compose services")
    run(["docker", "compose", "up", "-d"])
    print("[training] bootstrapping the three-team Attack/Defense match")
    run([sys.executable, "-m", "scripts.bootstrap_attack_defense_demo"])
    print("[training] starting all team and operations dashboards")
    start_dashboards()
    for item in DASHBOARDS:
        wait_for_url(f"http://127.0.0.1:{item['port']}/")
    print("\n" + "=" * 62)
    print("  START HERE  ->  http://localhost:5179/")
    print("  Open that single address and follow the on-screen guide:")
    print("  Attack  ->  Defense  ->  Results. No other ports needed.")
    print("  Login:  team01 / demo-team-01-change-me")
    print("=" * 62)
    print("\nAdvanced / instructor dashboards (optional):")
    for item in DASHBOARDS:
        if item["slug"] == "start":
            continue
        suffix = "/?mode=attack_defense" if item["slug"] == "livefire" else "/"
        print(f"  {item['name']:<15} http://localhost:{item['port']}{suffix}")
    print("  Team 02 login   team02 / demo-team-02-change-me")
    print("  Team 03 login   team03 / demo-team-03-change-me")
    print("\nBeginner Blue Team defense (one command):")
    print("  make beginner-defense     # or:  ./training defense")


def down() -> None:
    print("[training] stopping dashboard process groups")
    stop_dashboards()
    print("[training] stopping Docker Compose services")
    run(["docker", "compose", "down", "--remove-orphans"], check=False)


def status() -> None:
    run(["docker", "compose", "ps"], check=False)
    state_by_slug = {item.get("slug"): item for item in read_state()}
    print("\nDashboards:")
    for dashboard in DASHBOARDS:
        saved = state_by_slug.get(dashboard["slug"], {})
        pid = int(saved.get("pid", 0) or 0)
        running = bool(pid and is_managed_process(pid))
        print(
            f"  {'RUNNING' if running else 'STOPPED':<7} "
            f"{dashboard['name']:<15} http://localhost:{dashboard['port']}/"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage the complete local cyber training range")
    parser.add_argument("action", choices=("up", "down", "status"))
    args = parser.parse_args()
    if args.action == "up":
        try:
            up()
        except BaseException:
            print("\n[training] startup failed; removing the partial runtime", file=sys.stderr)
            down()
            raise
    elif args.action == "down":
        down()
    else:
        status()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
