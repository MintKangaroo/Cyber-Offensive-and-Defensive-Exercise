from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path

from fastapi import Header, HTTPException, Request


DATA_DIR = Path(os.environ.get("SERVICE_DATA_DIR", "/tmp/attack-defense-demo-service"))
DATA_DIR.mkdir(parents=True, exist_ok=True)


def attach_siem_access_log(app, asset_name: str | None = None) -> None:
    """감사 4.3: A/D 팀 서비스를 SIEM에 편입. 각 HTTP 요청을 트윈과 동일한 access-log JSON
    라인으로 siem_logs 볼륨에 남겨, SIEM이 A/D 공격도 탐지/기록하게 한다.
    shared/에 의존하지 않도록(데모 이미지에 shared가 없어도 되게) 자체 완결형으로 구현.
    로그 디렉터리가 없으면(로컬 dev) 조용히 미적용."""
    import logging

    asset = asset_name or os.environ.get("SIEM_ASSET", "attack_defense")
    team_id = os.environ.get("TEAM_ID", "default")
    log_dir = Path(os.environ.get("SIEM_LOG_DIR", "/var/log/siem"))
    logger = logging.getLogger(f"siem.ad.{asset}")
    if not logger.handlers:
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            h = logging.FileHandler(log_dir / f"{asset}_access.log")
            h.setFormatter(logging.Formatter("%(message)s"))
            logger.addHandler(h)
            logger.setLevel(logging.INFO)
        except OSError:
            return  # siem_logs 미마운트(로컬 dev) → 미적용

    @app.middleware("http")
    async def _siem_mw(request: Request, call_next):
        start = time.time()
        response = await call_next(request)
        xff = request.headers.get("x-forwarded-for", "")
        src_ip = xff.split(",")[0].strip() if xff else (request.client.host if request.client else None)
        try:
            logger.info(json.dumps({
                "ts": time.time(), "asset": asset, "endpoint": request.url.path,
                "method": request.method, "status": response.status_code, "src_ip": src_ip,
                "team_id": team_id, "ua": request.headers.get("user-agent"),
                "latency_ms": round((time.time() - start) * 1000, 2),
            }))
        except Exception:
            pass
        return response
MANAGEMENT_SECRET = os.environ.get(
    "ATTACK_DEFENSE_MANAGEMENT_TOKEN", "attack-defense-dev-management-token"
).encode()


def connect(name: str) -> sqlite3.Connection:
    conn = sqlite3.connect(DATA_DIR / name, timeout=5, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_identity(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """CREATE TABLE IF NOT EXISTS users(
             username TEXT PRIMARY KEY,password_hash TEXT NOT NULL,salt TEXT NOT NULL);
           CREATE TABLE IF NOT EXISTS sessions(
             token_hash TEXT PRIMARY KEY,username TEXT NOT NULL,created_at REAL NOT NULL);
           CREATE TABLE IF NOT EXISTS management_nonces(
             nonce TEXT PRIMARY KEY,seen_at REAL NOT NULL);"""
    )
    conn.commit()


def password_hash(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000).hex()


def register_user(conn: sqlite3.Connection, username: str, password: str) -> None:
    if not (3 <= len(username) <= 48 and username.replace("_", "").isalnum()):
        raise HTTPException(400, "invalid username")
    if not 10 <= len(password) <= 200:
        raise HTTPException(400, "password too short")
    salt = secrets.token_hex(12)
    try:
        conn.execute(
            "INSERT INTO users(username,password_hash,salt) VALUES(?,?,?)",
            (username, password_hash(password, salt), salt),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(409, "username already exists")


def login_user(conn: sqlite3.Connection, username: str, password: str) -> str:
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    actual = password_hash(password, row["salt"]) if row else password_hash(password, "missing")
    expected = row["password_hash"] if row else ("0" * 64)
    if not row or not hmac.compare_digest(actual, expected):
        raise HTTPException(401, "invalid credentials")
    token = secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO sessions(token_hash,username,created_at) VALUES(?,?,?)",
        (hashlib.sha256(token.encode()).hexdigest(), username, time.time()),
    )
    conn.commit()
    return token


def authenticated_user(conn: sqlite3.Connection, authorization: str) -> str:
    token = (authorization or "").removeprefix("Bearer ").strip()
    digest = hashlib.sha256(token.encode()).hexdigest()
    row = conn.execute("SELECT username FROM sessions WHERE token_hash=?", (digest,)).fetchone()
    if not token or not row:
        raise HTTPException(401, "authentication required")
    return str(row["username"])


async def require_management(
    request: Request,
    x_management_timestamp: str = Header(default=""),
    x_management_nonce: str = Header(default=""),
    x_management_signature: str = Header(default=""),
) -> None:
    try:
        timestamp = int(x_management_timestamp)
    except ValueError:
        raise HTTPException(401, "invalid management authentication")
    if abs(time.time() - timestamp) > 30 or not (16 <= len(x_management_nonce) <= 64):
        raise HTTPException(401, "invalid management authentication")
    body = await request.body()
    try:
        parsed = json.loads(body or b"{}")
    except ValueError:
        raise HTTPException(400, "invalid json")
    body_hash = hashlib.sha256(
        json.dumps(parsed, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    message = "\n".join(
        (request.method.upper(), request.url.path, str(timestamp), x_management_nonce, body_hash)
    ).encode()
    expected = hmac.new(MANAGEMENT_SECRET, message, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, x_management_signature):
        raise HTTPException(401, "invalid management authentication")
    conn = connect("service.db")
    init_identity(conn)
    try:
        conn.execute(
            "DELETE FROM management_nonces WHERE seen_at<?", (time.time() - 60,)
        )
        conn.execute(
            "INSERT INTO management_nonces(nonce,seen_at) VALUES(?,?)",
            (x_management_nonce, time.time()),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(409, "management request replayed")
    finally:
        conn.close()
