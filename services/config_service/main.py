"""
Config Service (04번 문서 5절 + 6절 구현)
===========================================
- 취약점 패치 상태를 중앙에서 관리(트윈이 3~5초 폴링, 재기동 없이 반영)
- 킬스위치(전체 훈련 강제 정지)
- 자산별 격리(quarantine) — EDR 콘솔의 "호스트 격리" 액션이 여기로 연결됨
- 모든 교관 조작은 audit log에 append-only로 기록(수정/삭제 불가)

실행: uvicorn services.config_service.main:app --port 8030
"""
from __future__ import annotations
import os
import sys
import time
import sqlite3
import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# shared.rbac 임포트를 위해 /app(리포 루트)을 경로에 추가(컨테이너 WORKDIR가 서비스 디렉토리라서 필요).
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from shared.rbac import require_role  # noqa: E402

APP_DIR = Path(__file__).parent
DB_PATH = APP_DIR / "config_service.db"
INSTRUCTOR_TOKEN = os.environ.get("INSTRUCTOR_TOKEN", "")  # 배포 시 반드시 설정, 기본값 미허용 정책은 배포 스크립트에서 강제

app = FastAPI(title="Config Service")

# EDR 콘솔(5173) + Live Fire 대시보드(5174)가 브라우저에서 직접 조회하므로 CORS 필요
# (격리상태/패치상태 fetch). 로컬 개발/훈련 범위이므로 localhost 전 포트 허용.
app.add_middleware(
    CORSMiddleware, allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS patch_state (
            asset TEXT, vuln_id TEXT, patched INTEGER DEFAULT 0,
            updated_at REAL, PRIMARY KEY (asset, vuln_id)
        );
        CREATE TABLE IF NOT EXISTS quarantine_state (
            asset TEXT PRIMARY KEY, quarantined INTEGER DEFAULT 0, updated_at REAL
        );
        CREATE TABLE IF NOT EXISTS global_state (
            key TEXT PRIMARY KEY, value TEXT
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            audit_id TEXT PRIMARY KEY,
            timestamp REAL,
            actor TEXT,
            action TEXT,
            target TEXT,
            before TEXT,
            after TEXT,
            reason TEXT,
            ip TEXT
        );
        """
    )
    conn.execute(
        "INSERT OR IGNORE INTO global_state (key, value) VALUES ('killswitch', 'false')"
    )
    conn.commit()
    conn.close()


init_db()


def _require_instructor(authorization: str) -> str:
    """교관 전용 조작 인가(RBAC). instructor 역할만 허용, 그 외 403 / 무효토큰 401.
    토큰 미설정 로컬 dev는 통과(actor='unauthenticated'). 24번 문서 4절."""
    return require_role(authorization, {"instructor"}).actor


def _audit(actor: str, action: str, target: str, before, after, reason: str, ip: str = "") -> None:
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_log (audit_id, timestamp, actor, action, target, before, after, reason, ip) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), time.time(), actor, action, target, str(before), str(after), reason, ip),
    )
    conn.commit()
    conn.close()


class PatchToggleRequest(BaseModel):
    asset: str
    vuln_id: str
    patched: bool
    reason: str


class QuarantineRequest(BaseModel):
    asset: str
    quarantined: bool
    reason: str


class KillswitchRequest(BaseModel):
    reason: str


@app.get("/health")
def health():
    return {"status": "ok", "service": "config_service"}


# ---------------------------------------------------------------------------
# 패치 상태 (트윈이 읽는 공개 엔드포인트 - 인증 불필요, 조회만)
# ---------------------------------------------------------------------------

@app.get("/config/patches")
def get_patches(asset: Optional[str] = None):
    conn = get_db()
    if asset:
        rows = conn.execute("SELECT vuln_id, patched FROM patch_state WHERE asset=?", (asset,)).fetchall()
    else:
        rows = conn.execute("SELECT asset, vuln_id, patched FROM patch_state").fetchall()
    conn.close()
    if asset:
        return {r["vuln_id"]: bool(r["patched"]) for r in rows}
    result: dict[str, dict[str, bool]] = {}
    for r in rows:
        result.setdefault(r["asset"], {})[r["vuln_id"]] = bool(r["patched"])
    return result


@app.get("/config/quarantine")
def get_quarantine(asset: Optional[str] = None):
    conn = get_db()
    if asset:
        row = conn.execute("SELECT quarantined FROM quarantine_state WHERE asset=?", (asset,)).fetchone()
        conn.close()
        return {"asset": asset, "quarantined": bool(row["quarantined"]) if row else False}
    rows = conn.execute("SELECT asset, quarantined FROM quarantine_state").fetchall()
    conn.close()
    return {r["asset"]: bool(r["quarantined"]) for r in rows}


@app.get("/config/killswitch")
def get_killswitch():
    conn = get_db()
    row = conn.execute("SELECT value FROM global_state WHERE key='killswitch'").fetchone()
    conn.close()
    return {"killswitch": row["value"] == "true"}


# ---------------------------------------------------------------------------
# 교관 전용 조작 (인증 필요, 전부 audit 기록)
# ---------------------------------------------------------------------------

@app.post("/instructor/patch/toggle")
def toggle_patch(req: PatchToggleRequest, authorization: str = Header(default="")):
    if not req.reason.strip():
        raise HTTPException(400, "reason is required for audit")
    actor = _require_instructor(authorization)

    conn = get_db()
    before = conn.execute(
        "SELECT patched FROM patch_state WHERE asset=? AND vuln_id=?", (req.asset, req.vuln_id)
    ).fetchone()
    before_val = bool(before["patched"]) if before else False

    conn.execute(
        """
        INSERT INTO patch_state (asset, vuln_id, patched, updated_at) VALUES (?, ?, ?, ?)
        ON CONFLICT(asset, vuln_id) DO UPDATE SET patched=excluded.patched, updated_at=excluded.updated_at
        """,
        (req.asset, req.vuln_id, int(req.patched), time.time()),
    )
    conn.commit()
    conn.close()

    _audit(actor, "patch_toggle", f"{req.asset}:{req.vuln_id}", before_val, req.patched, req.reason)
    return {"asset": req.asset, "vuln_id": req.vuln_id, "patched": req.patched}


@app.post("/instructor/quarantine")
def toggle_quarantine(req: QuarantineRequest, authorization: str = Header(default="")):
    """EDR 콘솔의 '호스트 격리' 액션이 호출하는 엔드포인트. 격리된 자산은 트윈이
    /health를 제외한 모든 엔드포인트에서 503을 반환하도록 스스로 확인한다(호스트 격리 시뮬레이션)."""
    if not req.reason.strip():
        raise HTTPException(400, "reason is required for audit")
    actor = _require_instructor(authorization)

    conn = get_db()
    before = conn.execute("SELECT quarantined FROM quarantine_state WHERE asset=?", (req.asset,)).fetchone()
    before_val = bool(before["quarantined"]) if before else False

    conn.execute(
        """
        INSERT INTO quarantine_state (asset, quarantined, updated_at) VALUES (?, ?, ?)
        ON CONFLICT(asset) DO UPDATE SET quarantined=excluded.quarantined, updated_at=excluded.updated_at
        """,
        (req.asset, int(req.quarantined), time.time()),
    )
    conn.commit()
    conn.close()

    _audit(actor, "quarantine_toggle", req.asset, before_val, req.quarantined, req.reason)
    return {"asset": req.asset, "quarantined": req.quarantined}


@app.post("/instructor/killswitch")
def killswitch(req: KillswitchRequest, authorization: str = Header(default="")):
    actor = _require_instructor(authorization)
    conn = get_db()
    conn.execute("UPDATE global_state SET value='true' WHERE key='killswitch'")
    conn.commit()
    conn.close()
    _audit(actor, "killswitch_activate", "global", False, True, req.reason)
    return {"killswitch": True}


@app.post("/instructor/killswitch/release")
def killswitch_release(req: KillswitchRequest, authorization: str = Header(default="")):
    actor = _require_instructor(authorization)
    conn = get_db()
    conn.execute("UPDATE global_state SET value='false' WHERE key='killswitch'")
    conn.commit()
    conn.close()
    _audit(actor, "killswitch_release", "global", True, False, req.reason)
    return {"killswitch": False}


@app.get("/instructor/audit")
def get_audit(limit: int = 200, action: Optional[str] = None):
    conn = get_db()
    if action:
        rows = conn.execute(
            "SELECT * FROM audit_log WHERE action=? ORDER BY timestamp DESC LIMIT ?", (action, limit)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return {"entries": [dict(r) for r in rows]}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8030)
