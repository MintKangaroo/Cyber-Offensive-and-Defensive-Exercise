"""Grid SCADA HMI — 국가 전력망 변전소 감시·제어(HMI) A/D 게임 서비스.

CCE/DEF CON A/D 본선의 "국가기반시설 타깃"용 취약 서비스. notes/vault 와 동일한 A/D 계약
(game 9000 / management 9001, register/login, /management/flags 주입·검증)을 따르되, 취약점을
ICS/OT 고전 결함으로 테마링한다.

**의도된 취약점 — 제어포인트 읽기 인가 누락(missing authorization)**:
SCADA HMI 는 제어포인트(Modbus/DNP3 의 레지스터·포인트에 대응)를 id 로 노출한다. 정상 운영자는
자기 권한 범위의 포인트만 읽어야 하지만, 이 HMI 는 **인증만 하고 인가를 안 해서** 인증된
아무 사용자나 `GET /api/points/{id}` 로 **restricted(안전·기밀) 포인트까지** 읽는다. 체커가
그 restricted 포인트에 라운드 플래그(예: 안전 인터록 해제 토큰)를 심고, 공격자는 포인트 id 를
훑어(enumeration) 플래그를 탈취한다. 실 ICS 사고의 전형(authentication ≠ authorization,
제어 함수에 접근제어 부재).

**방어(패치) — `PATCH_ICS_AUTHZ=true`**: 읽기에 소유자/공개(restricted=0) 검사를 추가해
남의 restricted 포인트 열람을 차단한다(benign 운영·자기 포인트 읽기는 그대로 동작).
"""
from __future__ import annotations

import hmac
import os
import sqlite3
import time

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from ..common import attach_siem_access_log
from ..common import (
    authenticated_user,
    connect,
    init_identity,
    login_user,
    register_user,
    require_management,
)


PATCH_ICS_AUTHZ = os.environ.get("PATCH_ICS_AUTHZ", "").lower() in {"1", "true", "yes"}


def db() -> sqlite3.Connection:
    conn = connect("service.db")
    init_identity(conn)
    conn.executescript(
        """CREATE TABLE IF NOT EXISTS control_points(
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             owner TEXT NOT NULL, label TEXT NOT NULL, value TEXT NOT NULL,
             restricted INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL);
           CREATE TABLE IF NOT EXISTS flag_slots(
             slot TEXT PRIMARY KEY, point_id INTEGER NOT NULL);"""
    )
    conn.commit()
    return conn


game_app = FastAPI(title="Grid SCADA HMI")
management_app = FastAPI(title="Grid SCADA HMI Management", docs_url=None, redoc_url=None)
game_app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=(
        r"https?://(localhost|127\.0\.0\.1|(\d{1,3}\.){3}\d{1,3}|"
        r"[\w-]+\.ts\.net)(:\d+)?"
    ),
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# 감사 4.3: A/D 팀 서비스를 SIEM 에 편입(요청을 access-log 로 남김).
attach_siem_access_log(game_app)


class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=48)
    password: str = Field(min_length=10, max_length=200)


class PointInput(BaseModel):
    label: str = Field(min_length=1, max_length=120)
    value: str = Field(min_length=1, max_length=256)


class FlagInput(BaseModel):
    slot: str = Field(min_length=1, max_length=100)
    value: str = Field(min_length=1, max_length=256)


@game_app.get("/health")
def health():
    return {"status": "healthy", "service": "grid-scada"}


@game_app.get("/api/version")
def version():
    return {"protocol": "ad-http-v1", "service": "grid-scada"}


@game_app.post("/api/register", status_code=201)
def register(req: Credentials):
    conn = db()
    try:
        register_user(conn, req.username, req.password)
    finally:
        conn.close()
    return {"registered": True}


@game_app.post("/api/login")
def login(req: Credentials):
    conn = db()
    try:
        token = login_user(conn, req.username, req.password)
    finally:
        conn.close()
    return {"access_token": token}


@game_app.post("/api/points", status_code=201)
def create_point(req: PointInput, authorization: str = Header(default="")):
    """운영자가 자기 제어포인트(예: 로컬 셋포인트 메모)를 등록. 정상 운영 흐름(benign)."""
    conn = db()
    try:
        user = authenticated_user(conn, authorization)
        cur = conn.execute(
            "INSERT INTO control_points(owner,label,value,restricted,created_at) "
            "VALUES(?,?,?,0,?)",
            (user, req.label, req.value, time.time()),
        )
        conn.commit()
        return {"id": cur.lastrowid}
    finally:
        conn.close()


@game_app.get("/api/points/{point_id}")
def read_point(point_id: int, authorization: str = Header(default="")):
    conn = db()
    try:
        user = authenticated_user(conn, authorization)
        if PATCH_ICS_AUTHZ:
            # 방어: 자기 소유이거나 공개(restricted=0) 포인트만 읽을 수 있다.
            row = conn.execute(
                "SELECT id,label,value,restricted,created_at FROM control_points "
                "WHERE id=? AND (owner=? OR restricted=0)",
                (point_id, user),
            ).fetchone()
        else:
            # 의도된 취약점: 인증만 하고 인가를 안 함 → 어떤 포인트든 id 로 읽힌다
            # (restricted 안전/기밀 포인트에 심긴 플래그가 그대로 유출).
            row = conn.execute(
                "SELECT id,label,value,restricted,created_at FROM control_points WHERE id=?",
                (point_id,),
            ).fetchone()
        if not row:
            raise HTTPException(404, "control point not found")
        return dict(row)
    finally:
        conn.close()


@management_app.get("/health")
def management_health():
    return {"status": "healthy"}


@management_app.post("/management/flags", dependencies=[Depends(require_management)])
def put_flag(req: FlagInput):
    """체커가 라운드 플래그를 restricted 제어포인트(안전 인터록 토큰)로 심는다."""
    conn = db()
    try:
        row = conn.execute(
            "SELECT point_id FROM flag_slots WHERE slot=?", (req.slot,)
        ).fetchone()
        if row:
            conn.execute(
                "UPDATE control_points SET value=? WHERE id=?", (req.value, row["point_id"])
            )
            point_id = row["point_id"]
        else:
            cur = conn.execute(
                "INSERT INTO control_points(owner,label,value,restricted,created_at) "
                "VALUES('__system__','SAFETY_INTERLOCK',?,1,?)",
                (req.value, time.time()),
            )
            point_id = cur.lastrowid
            conn.execute(
                "INSERT INTO flag_slots(slot,point_id) VALUES(?,?)", (req.slot, point_id)
            )
        conn.commit()
        return {
            "stored": True,
            "slot_hash": __import__("hashlib").sha256(req.slot.encode()).hexdigest(),
        }
    finally:
        conn.close()


@management_app.post("/management/flags/verify", dependencies=[Depends(require_management)])
def verify_flag(req: FlagInput):
    conn = db()
    try:
        row = conn.execute(
            """SELECT p.value FROM flag_slots f JOIN control_points p ON p.id=f.point_id
               WHERE f.slot=?""",
            (req.slot,),
        ).fetchone()
        return {"verified": bool(row and hmac.compare_digest(row["value"], req.value))}
    finally:
        conn.close()
