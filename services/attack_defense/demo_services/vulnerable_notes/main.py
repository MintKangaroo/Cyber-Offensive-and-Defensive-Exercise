from __future__ import annotations

import hmac
import os
import sqlite3
import time

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from ..common import (
    authenticated_user,
    connect,
    init_identity,
    login_user,
    register_user,
    require_management,
)


PATCH_IDOR = os.environ.get("PATCH_IDOR", "").lower() in {"1", "true", "yes"}


def db() -> sqlite3.Connection:
    conn = connect("service.db")
    init_identity(conn)
    conn.executescript(
        """CREATE TABLE IF NOT EXISTS notes(
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             owner TEXT NOT NULL,content TEXT NOT NULL,created_at REAL NOT NULL);
           CREATE TABLE IF NOT EXISTS flag_slots(
             slot TEXT PRIMARY KEY,note_id INTEGER NOT NULL);"""
    )
    conn.commit()
    return conn


game_app = FastAPI(title="Vulnerable Notes")
management_app = FastAPI(title="Vulnerable Notes Management", docs_url=None, redoc_url=None)
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


class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=48)
    password: str = Field(min_length=10, max_length=200)


class NoteInput(BaseModel):
    content: str = Field(min_length=1, max_length=4096)


class FlagInput(BaseModel):
    slot: str = Field(min_length=1, max_length=100)
    value: str = Field(min_length=1, max_length=256)


@game_app.get("/health")
def health():
    return {"status": "healthy", "service": "vulnerable-notes"}


@game_app.get("/api/version")
def version():
    return {"protocol": "ad-http-v1", "service": "vulnerable-notes"}


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


@game_app.post("/api/notes", status_code=201)
def create_note(req: NoteInput, authorization: str = Header(default="")):
    conn = db()
    try:
        user = authenticated_user(conn, authorization)
        cur = conn.execute(
            "INSERT INTO notes(owner,content,created_at) VALUES(?,?,?)",
            (user, req.content, time.time()),
        )
        conn.commit()
        return {"id": cur.lastrowid}
    finally:
        conn.close()


@game_app.get("/api/notes/{note_id}")
def get_note(note_id: int, authorization: str = Header(default="")):
    conn = db()
    try:
        user = authenticated_user(conn, authorization)
        if PATCH_IDOR:
            row = conn.execute(
                "SELECT id,content,created_at FROM notes WHERE id=? AND owner=?",
                (note_id, user),
            ).fetchone()
        else:
            # Intended training vulnerability: authenticated users can read a
            # note by numeric identifier without ownership verification.
            row = conn.execute(
                "SELECT id,content,created_at FROM notes WHERE id=?", (note_id,)
            ).fetchone()
        if not row:
            raise HTTPException(404, "note not found")
        return dict(row)
    finally:
        conn.close()


@management_app.get("/health")
def management_health():
    return {"status": "healthy"}


@management_app.post("/management/flags", dependencies=[Depends(require_management)])
def put_flag(req: FlagInput):
    conn = db()
    try:
        row = conn.execute("SELECT note_id FROM flag_slots WHERE slot=?", (req.slot,)).fetchone()
        if row:
            conn.execute("UPDATE notes SET content=? WHERE id=?", (req.value, row["note_id"]))
            note_id = row["note_id"]
        else:
            cur = conn.execute(
                "INSERT INTO notes(owner,content,created_at) VALUES('__system__',?,?)",
                (req.value, time.time()),
            )
            note_id = cur.lastrowid
            conn.execute("INSERT INTO flag_slots(slot,note_id) VALUES(?,?)", (req.slot, note_id))
        conn.commit()
        return {"stored": True, "slot_hash": __import__("hashlib").sha256(req.slot.encode()).hexdigest()}
    finally:
        conn.close()


@management_app.post("/management/flags/verify", dependencies=[Depends(require_management)])
def verify_flag(req: FlagInput):
    conn = db()
    try:
        row = conn.execute(
            """SELECT n.content FROM flag_slots f JOIN notes n ON n.id=f.note_id
               WHERE f.slot=?""", (req.slot,)
        ).fetchone()
        return {"verified": bool(row and hmac.compare_digest(row["content"], req.value))}
    finally:
        conn.close()
