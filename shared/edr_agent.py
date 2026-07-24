"""
EDR Agent (Falcon의 'Sensor'에 대응)
======================================
트윈 컨테이너 프로세스 안에서 백그라운드 스레드로 실행된다(별도 컨테이너 아님, 배포 단순화).
5초마다 psutil로 프로세스/네트워크 스냅샷을 찍어 EDR Backend에 전송하고,
동시에 대기 중인 kill 명령을 폴링해 **이 프로세스 공간 안에서** 실제로 실행한다.

중요: 실제 프로세스 종료는 반드시 트윈 컨테이너 내부(=이 에이전트)에서 수행해야 한다.
EDR Backend는 별도 프로세스/컨테이너라 트윈의 pid 네임스페이스에 직접 접근할 수 없기 때문에,
"명령 큐"를 두고 에이전트가 폴링해서 대신 실행하는 구조를 쓴다.

사용법 (트윈의 main.py에서):
    from shared.edr_agent import start_edr_agent
    start_edr_agent(asset_name="ground_station")   # FastAPI startup에서 1회 호출
"""
from __future__ import annotations
import os
import time
import threading
from typing import Optional

try:
    import psutil
except ImportError:
    psutil = None  # psutil 미설치 환경에서도 트윈 자체는 죽지 않도록

import requests

EDR_BACKEND_URL = os.environ.get("EDR_BACKEND_URL", "http://edr_backend:8080")
_POLL_INTERVAL_SEC = 5
_TIMEOUT = 2.0

# 이 프로세스(트윈 서버 자신)의 pid. EDR Backend에 보고해 "이 pid는 절대 보호"로 등록시킨다.
# 공격으로 생성된 프로세스가 우연히 같은 이름(python3 등)이어도 pid가 다르므로 안전하게 구분된다.
SERVER_PID = os.getpid()


def _snapshot_processes() -> list[dict]:
    """현재 컨테이너 내 프로세스 스냅샷. psutil 미설치 시 빈 리스트(에이전트 비활성)."""
    if psutil is None:
        return []
    procs = []
    for p in psutil.process_iter(["pid", "ppid", "name", "cmdline", "create_time", "username"]):
        try:
            info = p.info
            connections = []
            try:
                for c in p.connections(kind="inet"):
                    connections.append({
                        "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                        "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                        "status": c.status,
                    })
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            procs.append({
                "pid": info["pid"],
                "ppid": info["ppid"],
                "name": info["name"],
                "cmdline": " ".join(info["cmdline"] or []),
                "create_time": info["create_time"],
                "username": info.get("username"),
                "connections": connections,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return procs


def _send_snapshot(asset: str, processes: list[dict]) -> None:
    payload = {"asset": asset, "timestamp": time.time(), "server_pid": SERVER_PID, "processes": processes}
    try:
        requests.post(f"{EDR_BACKEND_URL}/edr/ingest", json=payload, timeout=_TIMEOUT)
    except requests.exceptions.RequestException:
        pass  # EDR Backend 다운이어도 트윈 서비스 자체는 절대 영향받지 않음


def _fetch_pending_kill_commands(asset: str) -> list[dict]:
    try:
        r = requests.get(f"{EDR_BACKEND_URL}/edr/hosts/{asset}/kill-commands/pending", timeout=_TIMEOUT)
        return r.json().get("commands", [])
    except requests.exceptions.RequestException:
        return []


def _ack_kill_command(command_id: str, status: str, detail: str) -> None:
    try:
        requests.post(
            f"{EDR_BACKEND_URL}/edr/kill-commands/{command_id}/ack",
            json={"status": status, "result_detail": detail},
            timeout=_TIMEOUT,
        )
    except requests.exceptions.RequestException:
        pass  # ack 유실 시에도 최소한 kill 자체는 이미 시도/완료된 상태


def _execute_kill(pid: int) -> tuple[str, str]:
    """실제 os.kill() 실행. 이 함수가 실행되는 프로세스(에이전트 = 트윈 서버 자신)와
    동일한 pid는 절대 실행하지 않는다(방어적 이중 체크 — EDR Backend도 이미 server_pid로
    거부하지만, 네트워크 지연 중 상태가 바뀔 가능성에 대비한 로컬 재검증)."""
    if pid == SERVER_PID:
        return "failed", f"refused: pid {pid} is this agent's own server_pid"

    if psutil is None:
        return "failed", "psutil not installed in this container"

    if not psutil.pid_exists(pid):
        return "done", f"pid {pid} already gone (nothing to kill)"

    try:
        proc = psutil.Process(pid)
        proc.terminate()  # SIGTERM 먼저(정상 종료 기회)
        try:
            proc.wait(timeout=3)
            return "done", f"pid {pid} terminated via SIGTERM"
        except psutil.TimeoutExpired:
            proc.kill()  # 3초 내 안 죽으면 SIGKILL로 승격
            proc.wait(timeout=2)
            return "done", f"pid {pid} force-killed via SIGKILL (SIGTERM ignored)"
    except psutil.NoSuchProcess:
        return "done", f"pid {pid} exited during kill attempt"
    except psutil.AccessDenied:
        return "failed", f"access denied killing pid {pid} (insufficient container privileges)"
    except Exception as e:
        return "failed", f"unexpected error: {e}"


def _process_pending_kills(asset: str) -> None:
    for cmd in _fetch_pending_kill_commands(asset):
        status, detail = _execute_kill(cmd["pid"])
        _ack_kill_command(cmd["id"], status, detail)


def _agent_loop(asset: str) -> None:
    while True:
        try:
            snapshot = _snapshot_processes()
            if snapshot:
                _send_snapshot(asset, snapshot)
            _process_pending_kills(asset)
        except Exception:
            pass  # 어떤 예외도 트윈 메인 서비스로 전파되지 않게 완전히 격리
        time.sleep(_POLL_INTERVAL_SEC)


_started: dict[str, bool] = {}


def start_edr_agent(asset_name: str) -> Optional[threading.Thread]:
    """FastAPI startup 이벤트에서 1회 호출. 이미 시작됐으면 재시작하지 않음."""
    if _started.get(asset_name):
        return None
    _started[asset_name] = True
    t = threading.Thread(target=_agent_loop, args=(asset_name,), daemon=True)
    t.start()
    return t
