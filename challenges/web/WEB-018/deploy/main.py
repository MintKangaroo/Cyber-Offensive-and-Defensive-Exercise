"""WEB-018 배포용 서비스 — 국가 병원 EMR 응급 포털(NoSQL 인젝션 인증우회).

로그인 조회가 문서 저장소(Mongo 계열) 시맨틱으로 사용자/비밀번호를 매칭하는데, 요청 JSON 의
password(및 username)를 문자열이 아닌 '연산자 객체'로도 받아 그대로 질의에 넣는다. 따라서
password 에 {"$ne": ""} 같은 연산자를 주면 임의 사용자의 비밀번호 검사를 우회한다(NoSQLi).
관리자로 로그인하면 응급 대응 문서(flag)를 열람할 수 있다.

PATCH_WEB_018=true 면 username/password 를 문자열로만 강제(연산자 객체 거부)해 차단한다.
"""
import hashlib
import os
import re as _re
import secrets

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import Any

app = FastAPI(title="WEB-018 Hospital EMR Portal (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_WEB_018", "false").lower() == "true"


def static_flag() -> str:
    sig = hashlib.sha256(f"WEB-018:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{hospital_nosqli_{sig}}}"


# 문서 저장소(더미). admin 비밀번호는 예측 불가한 강한 값(정상 로그인은 사실상 불가 → NoSQLi 필요)
_USERS = [
    {"username": "admin", "password": secrets.token_urlsafe(24), "role": "admin"},
    {"username": "nurse01", "password": "spring-2025-ward", "role": "staff"},
]
_SESSIONS: dict[str, dict] = {}


def _match_field(stored: str, cond: Any) -> bool:
    """Mongo 계열 매칭: 문자열이면 동등, 딕셔너리면 연산자 적용($eq/$ne/$gt/$regex/$in)."""
    if isinstance(cond, dict):
        for op, val in cond.items():
            if op == "$eq" and not (stored == val):
                return False
            elif op == "$ne" and not (stored != val):
                return False
            elif op == "$gt" and not (stored > str(val)):
                return False
            elif op == "$regex" and not _re.search(str(val), stored):
                return False
            elif op == "$in" and stored not in (val or []):
                return False
        return True
    return stored == cond


class LoginReq(BaseModel):
    username: Any
    password: Any


@app.get("/health")
def health():
    return {"status": "ok", "patched": PATCHED, "service": "hospital-emr"}


@app.get("/api/version")
def version():
    return {"protocol": "ad-http-v1", "service": "hospital-emr"}


@app.post("/api/login")
def login(req: LoginReq):
    if PATCHED:
        # 방어: 연산자 객체 거부 — 문자열만 허용
        if not isinstance(req.username, str) or not isinstance(req.password, str):
            raise HTTPException(400, "잘못된 자격증명 형식")
    # 취약: username/password 를 연산자 객체로도 질의에 그대로 사용
    for user in _USERS:
        if _match_field(user["username"], req.username) and _match_field(user["password"], req.password):
            token = secrets.token_urlsafe(18)
            _SESSIONS[token] = user
            return {"access_token": token, "role": user["role"], "username": user["username"]}
    raise HTTPException(401, "로그인 실패")


def _current(authorization: str = Header(default="")) -> dict:
    token = authorization.removeprefix("Bearer ").strip()
    u = _SESSIONS.get(token)
    if not u:
        raise HTTPException(401, "인증 필요")
    return u


@app.get("/api/records/emergency")
def emergency(user: dict = Depends(_current)):
    if user.get("role") != "admin":
        raise HTTPException(403, "관리자 권한 필요")
    return {"emergency_response_token": static_flag()}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8118)
