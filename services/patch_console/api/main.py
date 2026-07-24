"""
Patch Console API
====================
Blue팀 대시보드가 호출하는 "패치 적용" 엔드포인트.
화이트리스트된 vuln_id -> playbook만 ansible-playbook으로 실행하고,
결과를 audit log에 남긴 뒤 Config Service의 patched 상태를 갱신한다.

실행: uvicorn services.patch_console.api.main:app --port 8060
"""
from __future__ import annotations
import subprocess
import time
import sqlite3
import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
import httpx

import sys
sys.path.append(str(Path(__file__).parent.parent.parent.parent))
from services.patch_console.whitelist import resolve_playbook_path, is_whitelisted, list_available  # noqa: E402

APP_DIR = Path(__file__).parent
DB_PATH = APP_DIR / "patch_console_audit.db"
CONFIG_SERVICE_URL = "http://config_service:8030"
INSTRUCTOR_TOKEN_ENV = "INSTRUCTOR_TOKEN"   # 실행 환경변수에서 읽음(하드코딩 금지)
ANSIBLE_TIMEOUT_SEC = 60

app = FastAPI(title="Patch Console API")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS patch_runs (
            run_id TEXT PRIMARY KEY,
            vuln_id TEXT,
            asset TEXT,
            team_id TEXT,
            actor TEXT,
            reason TEXT,
            status TEXT,          -- running|success|failed
            stdout TEXT,
            rc INTEGER,
            started_at REAL,
            finished_at REAL
        )
        """
    )
    conn.commit()
    conn.close()


init_db()


class PatchApplyRequest(BaseModel):
    vuln_id: str
    team_id: str = "default"
    reason: str          # 감사 필수(빈 문자열이면 400)


@app.get("/health")
def health():
    return {"status": "ok", "service": "patch_console"}


@app.get("/patch/available")
def available():
    return {"playbooks": list_available()}


@app.post("/patch/apply")
async def apply_patch(req: PatchApplyRequest, authorization: str = Header(default="")):
    if not req.reason.strip():
        raise HTTPException(400, "reason is required for audit")
    if not is_whitelisted(req.vuln_id):
        raise HTTPException(400, f"'{req.vuln_id}' is not a whitelisted patch target")

    playbook_path = resolve_playbook_path(req.vuln_id)
    if playbook_path is None:
        # whitelist엔 있으나 파일이 없거나 경로검증 실패 -> 안전하게 거부
        raise HTTPException(500, "playbook not found or path validation failed")

    run_id = str(uuid.uuid4())
    started_at = time.time()

    conn = get_db()
    conn.execute(
        "INSERT INTO patch_runs (run_id, vuln_id, team_id, actor, reason, status, started_at) "
        "VALUES (?, ?, ?, ?, ?, 'running', ?)",
        (run_id, req.vuln_id, req.team_id, "blue", req.reason, started_at),
    )
    conn.commit()
    conn.close()

    # ansible-playbook 실행 (인벤토리는 고정 파일, 대상 그룹은 화이트리스트에서만 결정)
    inventory = str(APP_DIR.parent / "inventory.yml")
    cmd = ["ansible-playbook", "-i", inventory, str(playbook_path)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=ANSIBLE_TIMEOUT_SEC)
        status = "success" if proc.returncode == 0 else "failed"
        stdout = (proc.stdout + proc.stderr)[-8000:]  # 과도한 로그 방지
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        status, stdout, rc = "failed", "ansible-playbook timed out", -1
    except FileNotFoundError:
        status, stdout, rc = "failed", "ansible-playbook not installed in this environment", -1

    finished_at = time.time()
    conn = get_db()
    conn.execute(
        "UPDATE patch_runs SET status=?, stdout=?, rc=?, finished_at=? WHERE run_id=?",
        (status, stdout, rc, finished_at, run_id),
    )
    conn.commit()
    conn.close()

    # 성공 시 Config Service에 patched=true 반영(플레이북 내부에서도 호출하지만,
    # 이중 안전장치로 API 레벨에서도 한 번 더 보증)
    if status == "success":
        await _notify_config_service(req.vuln_id, req.team_id, req.reason)

    return {"run_id": run_id, "status": status, "rc": rc, "duration_sec": round(finished_at - started_at, 2),
           "log_tail": stdout[-2000:]}


async def _notify_config_service(vuln_id: str, team_id: str, reason: str) -> None:
    import os
    from services.patch_console.whitelist import WHITELIST
    asset = WHITELIST.get(vuln_id, {}).get("asset")
    token = os.environ.get(INSTRUCTOR_TOKEN_ENV, "")
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            await client.post(
                f"{CONFIG_SERVICE_URL}/instructor/patch/toggle",
                json={"asset": asset, "vuln_id": vuln_id, "patched": True,
                     "reason": f"patch_console:{reason}"},
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError:
        pass  # Config Service 다운이어도 플레이북 자체 결과는 이미 기록됨


@app.get("/patch/status/{vuln_id}")
def patch_status(vuln_id: str):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM patch_runs WHERE vuln_id=? ORDER BY started_at DESC LIMIT 1", (vuln_id,)
    ).fetchone()
    conn.close()
    if not row:
        return {"vuln_id": vuln_id, "status": "never_run"}
    return dict(row)


@app.get("/patch/history")
def patch_history(team_id: Optional[str] = None, limit: int = 50):
    conn = get_db()
    if team_id:
        rows = conn.execute(
            "SELECT * FROM patch_runs WHERE team_id=? ORDER BY started_at DESC LIMIT ?", (team_id, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM patch_runs ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
    conn.close()
    return {"runs": [dict(r) for r in rows]}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8060)
