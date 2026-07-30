"""
Auth 서비스 (P0-2) — 로그인·세션·JWT·감사
============================================
- 사용자/팀 계정(sqlite, PBKDF2 해시), CSV 일괄 등록(교관).
- 로그인 → 단기 access JWT(15분) + refresh(8시간), role/team_id/match_id 클레임. httpOnly 쿠키.
- POST /auth/revoke 로 즉시 폐기(부정행위자 차단). GET /auth/verify 는 gateway auth_request용.
- 서명키(AUTH_JWT_SECRET) 회전 가능. shared/rbac.py 가 이 JWT를 검증한다.

주의: 훈련 플랫폼. 비밀번호는 PBKDF2-HMAC-SHA256(200k)로 해시(argon2 대신 stdlib, 의존성 최소화).
"""
from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import os
import secrets
import time
import uuid
from pathlib import Path

import jwt
from fastapi import Cookie, FastAPI, Header, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

APP_DIR = Path(__file__).parent
DB_PATH = Path(os.environ.get("DATA_DIR", str(APP_DIR))) / "auth.db"
JWT_SECRET = os.environ.get("AUTH_JWT_SECRET", "").strip() or secrets.token_hex(32)
ACCESS_TTL = int(os.environ.get("AUTH_ACCESS_TTL", "900"))       # 15분
REFRESH_TTL = int(os.environ.get("AUTH_REFRESH_TTL", "28800"))   # 8시간
ROLES = ("instructor", "operator", "competitor", "red", "blue", "observer")
COOKIE = "cr_token"

app = FastAPI(title="Auth")
app.add_middleware(
    CORSMiddleware, allow_origin_regex=r"https?://(localhost|127\.0\.0\.1|(\d{1,3}\.){3}\d{1,3}|[\w-]+\.ts\.net)(:\d+)?",
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

import sqlite3


def _db():
    c = sqlite3.connect(DB_PATH); c.row_factory = sqlite3.Row; return c


def _init():
    c = _db()
    c.execute("""CREATE TABLE IF NOT EXISTS users(
        username TEXT PRIMARY KEY, pw_hash TEXT, salt TEXT, role TEXT,
        team_id TEXT, match_id TEXT, created_at REAL)""")
    c.execute("""CREATE TABLE IF NOT EXISTS revoked(jti TEXT PRIMARY KEY, at REAL)""")
    c.commit(); c.close()


def _hash(pw: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000).hex()


def _verify_pw(pw: str, salt: str, expect: str) -> bool:
    return hmac.compare_digest(_hash(pw, salt), expect)


def _add_user(username: str, password: str, role: str, team_id: str = "", match_id: str = ""):
    if role not in ROLES:
        raise ValueError(f"invalid role {role}")
    salt = secrets.token_hex(8)
    c = _db()
    c.execute("INSERT OR REPLACE INTO users VALUES(?,?,?,?,?,?,?)",
              (username, _hash(password, salt), salt, role, team_id, match_id, time.time()))
    c.commit(); c.close()


def _issue(username: str, role: str, team_id: str, match_id: str, ttl: int, typ: str) -> str:
    now = int(time.time())
    return jwt.encode({"sub": username, "role": role, "team_id": team_id, "match_id": match_id,
                       "type": typ, "jti": uuid.uuid4().hex, "iat": now, "exp": now + ttl},
                      JWT_SECRET, algorithm="HS256")


def _decode(token: str, typ: str | None = None) -> dict:
    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError as e:
        raise HTTPException(401, f"invalid token: {e}")
    if typ and claims.get("type") != typ:
        raise HTTPException(401, "wrong token type")
    c = _db()
    revoked = c.execute("SELECT 1 FROM revoked WHERE jti=?", (claims.get("jti"),)).fetchone()
    c.close()
    if revoked:
        raise HTTPException(401, "token revoked")
    return claims


def _require_instructor(authorization: str, cookie: str | None) -> dict:
    tok = (authorization or "").replace("Bearer ", "").strip() or (cookie or "")
    claims = _decode(tok, "access")
    if claims.get("role") != "instructor":
        raise HTTPException(403, "instructor only")
    return claims


_init()
# 최초 부팅 시 교관 계정 시드(없을 때만). 비번은 AUTH_ADMIN_PASSWORD 또는 생성 후 로그 출력.
def _seed():
    c = _db(); n = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]; c.close()
    if n == 0:
        pw = os.environ.get("AUTH_ADMIN_PASSWORD") or secrets.token_urlsafe(12)
        _add_user("instructor", pw, "instructor")
        print(f"[auth] 시드 교관 계정 생성: instructor / {pw}  (AUTH_ADMIN_PASSWORD로 고정 가능)")


_seed()


class LoginReq(BaseModel):
    username: str
    password: str


class RegisterReq(BaseModel):
    username: str
    password: str
    role: str
    team_id: str = ""
    match_id: str = ""


@app.get("/health")
def health():
    c = _db(); n = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]; c.close()
    return {"service": "auth", "users": n}


@app.post("/auth/login")
def login(req: LoginReq, response: Response):
    c = _db(); row = c.execute("SELECT * FROM users WHERE username=?", (req.username,)).fetchone(); c.close()
    if not row or not _verify_pw(req.password, row["salt"], row["pw_hash"]):
        raise HTTPException(401, "invalid credentials")
    access = _issue(row["username"], row["role"], row["team_id"] or "", row["match_id"] or "", ACCESS_TTL, "access")
    refresh = _issue(row["username"], row["role"], row["team_id"] or "", row["match_id"] or "", REFRESH_TTL, "refresh")
    # httpOnly 쿠키(same-origin gateway). Secure는 https 뒤에서.
    response.set_cookie(COOKIE, access, httponly=True, samesite="lax", max_age=ACCESS_TTL, path="/")
    response.set_cookie("cr_refresh", refresh, httponly=True, samesite="lax", max_age=REFRESH_TTL, path="/")
    return {"role": row["role"], "team_id": row["team_id"], "match_id": row["match_id"],
            "access_token": access, "expires_in": ACCESS_TTL}


@app.post("/auth/refresh")
def refresh(response: Response, cr_refresh: str | None = Cookie(default=None)):
    if not cr_refresh:
        raise HTTPException(401, "no refresh token")
    claims = _decode(cr_refresh, "refresh")
    access = _issue(claims["sub"], claims["role"], claims.get("team_id", ""), claims.get("match_id", ""), ACCESS_TTL, "access")
    response.set_cookie(COOKIE, access, httponly=True, samesite="lax", max_age=ACCESS_TTL, path="/")
    return {"access_token": access, "expires_in": ACCESS_TTL}


@app.post("/auth/logout")
def logout(response: Response):
    response.delete_cookie(COOKIE, path="/"); response.delete_cookie("cr_refresh", path="/")
    return {"logged_out": True}


@app.get("/auth/me")
def me(authorization: str = Header(default=""), cr_token: str | None = Cookie(default=None)):
    tok = (authorization or "").replace("Bearer ", "").strip() or (cr_token or "")
    claims = _decode(tok, "access")
    return {"username": claims["sub"], "role": claims["role"], "team_id": claims.get("team_id"),
            "match_id": claims.get("match_id")}


@app.get("/auth/verify")
def verify(response: Response, authorization: str = Header(default=""), cr_token: str | None = Cookie(default=None)):
    """gateway auth_request용 — 유효하면 200 + X-Auth-* 헤더(백엔드에 Bearer 주입), 아니면 401."""
    tok = (authorization or "").replace("Bearer ", "").strip() or (cr_token or "")
    claims = _decode(tok, "access")
    response.headers["X-Auth-Role"] = claims["role"]
    response.headers["X-Auth-User"] = claims["sub"]
    response.headers["X-Auth-Token"] = tok
    return {"ok": True, "role": claims["role"]}


@app.post("/auth/register")
def register(req: RegisterReq, authorization: str = Header(default=""), cr_token: str | None = Cookie(default=None)):
    _require_instructor(authorization, cr_token)
    _add_user(req.username, req.password, req.role, req.team_id, req.match_id)
    return {"registered": req.username, "role": req.role}


class BulkReq(BaseModel):
    csv: str   # "username,password,role,team_id,match_id" per line (헤더 허용)


@app.post("/auth/users/bulk")
def bulk(req: BulkReq, authorization: str = Header(default=""), cr_token: str | None = Cookie(default=None)):
    _require_instructor(authorization, cr_token)
    added, errors = 0, []
    for i, r in enumerate(csv.reader(io.StringIO(req.csv))):
        if not r or r[0].strip().lower() in ("username", "#"):
            continue
        try:
            _add_user(r[0].strip(), r[1].strip(), r[2].strip(),
                      r[3].strip() if len(r) > 3 else "", r[4].strip() if len(r) > 4 else "")
            added += 1
        except (IndexError, ValueError) as e:
            errors.append(f"line {i+1}: {e}")
    return {"added": added, "errors": errors}


class RevokeReq(BaseModel):
    jti: str = ""
    username: str = ""   # username이면 그 유저의 향후 토큰 무효화는 불가(정적), jti 폐기 권장


@app.post("/auth/revoke")
def revoke(req: RevokeReq, authorization: str = Header(default=""), cr_token: str | None = Cookie(default=None)):
    _require_instructor(authorization, cr_token)
    if not req.jti:
        raise HTTPException(400, "jti 필요(부정행위자 토큰의 jti). /auth/me 로 확인")
    c = _db(); c.execute("INSERT OR REPLACE INTO revoked VALUES(?,?)", (req.jti, time.time())); c.commit(); c.close()
    return {"revoked": req.jti}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8051)
