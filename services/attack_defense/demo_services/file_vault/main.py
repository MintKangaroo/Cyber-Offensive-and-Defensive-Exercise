from __future__ import annotations

import hmac
import os
import sqlite3
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from ..common import (
    DATA_DIR,
    authenticated_user,
    connect,
    init_identity,
    login_user,
    register_user,
    require_management,
)


PATCH_TRAVERSAL = os.environ.get("PATCH_TRAVERSAL", "").lower() in {"1", "true", "yes"}
USERS_DIR = DATA_DIR / "users"
SYSTEM_DIR = DATA_DIR / "system"
USERS_DIR.mkdir(parents=True, exist_ok=True)
SYSTEM_DIR.mkdir(parents=True, exist_ok=True)


def db() -> sqlite3.Connection:
    conn = connect("service.db")
    init_identity(conn)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS flag_slots(slot TEXT PRIMARY KEY,path TEXT NOT NULL)"
    )
    conn.commit()
    return conn


game_app = FastAPI(title="File Vault")
management_app = FastAPI(title="File Vault Management", docs_url=None, redoc_url=None)
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


class FileInput(BaseModel):
    path: str = Field(min_length=1, max_length=160)
    content: str = Field(max_length=8192)


class FlagInput(BaseModel):
    slot: str = Field(min_length=1, max_length=100)
    value: str = Field(min_length=1, max_length=256)


def _user_root(user: str) -> Path:
    root = USERS_DIR / user
    root.mkdir(parents=True, exist_ok=True)
    return root


def _safe_path(root: Path, requested: str, enforce: bool) -> Path:
    candidate = (root / requested).resolve()
    if enforce and root.resolve() not in candidate.parents and candidate != root.resolve():
        raise HTTPException(404, "file not found")
    return candidate


@game_app.get("/health")
def health():
    return {"status": "healthy", "service": "file-vault"}


@game_app.get("/api/version")
def version():
    return {"protocol": "ad-http-v1", "service": "file-vault"}


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


@game_app.post("/api/files", status_code=201)
def upload(req: FileInput, authorization: str = Header(default="")):
    conn = db()
    try:
        user = authenticated_user(conn, authorization)
    finally:
        conn.close()
    target = _safe_path(_user_root(user), req.path, True)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(req.content, encoding="utf-8")
    return {"stored": True, "path": req.path}


@game_app.get("/api/files")
def download(path: str, authorization: str = Header(default="")):
    conn = db()
    try:
        user = authenticated_user(conn, authorization)
    finally:
        conn.close()
    # Intended training vulnerability: the base image resolves `..` but does
    # not enforce containment for reads. Directory metadata is also returned
    # by the vulnerable image so an attacker can discover a traversed file
    # before exfiltrating it; the patched image rejects the path first.
    target = _safe_path(_user_root(user), path, PATCH_TRAVERSAL)
    try:
        if target.is_dir():
            return {
                "path": path,
                "entries": sorted(item.name for item in target.iterdir()),
            }
        return {"path": path, "content": target.read_text(encoding="utf-8")}
    except (OSError, UnicodeError):
        raise HTTPException(404, "file not found")


@management_app.get("/health")
def management_health():
    return {"status": "healthy"}


@management_app.post("/management/flags", dependencies=[Depends(require_management)])
def put_flag(req: FlagInput):
    digest = __import__("hashlib").sha256(req.slot.encode()).hexdigest()
    target = SYSTEM_DIR / f"{digest}.txt"
    target.write_text(req.value, encoding="utf-8")
    conn = db()
    try:
        conn.execute(
            """INSERT INTO flag_slots(slot,path) VALUES(?,?)
               ON CONFLICT(slot) DO UPDATE SET path=excluded.path""",
            (req.slot, target.name),
        )
        conn.commit()
    finally:
        conn.close()
    return {"stored": True, "slot_hash": digest}


@management_app.post("/management/flags/verify", dependencies=[Depends(require_management)])
def verify_flag(req: FlagInput):
    conn = db()
    try:
        row = conn.execute("SELECT path FROM flag_slots WHERE slot=?", (req.slot,)).fetchone()
    finally:
        conn.close()
    try:
        actual = (SYSTEM_DIR / row["path"]).read_text(encoding="utf-8") if row else ""
    except OSError:
        actual = ""
    return {"verified": hmac.compare_digest(actual, req.value)}
