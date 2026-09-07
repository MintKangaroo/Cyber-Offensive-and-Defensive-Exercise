"""WEB-011 배포용 취약 서비스 — 한국석유공사 유가알림 포털(권한 상승 / Mass Assignment).

실제 2025 사이버공격방어대회 본선 "석유공사" 문제의 권한 상승 결함을 재구성한 훈련용 서비스.
회원가입(POST /api/auth/register)이 **클라이언트가 보낸 is_admin 필드를 그대로 신뢰**해
계정 권한에 반영한다 → 일반 가입 요청에 is_admin:true 를 넣으면 관리자가 된다(mass assignment).
관리자 전용 GET /api/admin/flag 가 비상 대응 문서(플래그)를 노출한다.

PATCH_WEB_011=true 면 서버가 is_admin 을 무시하고 항상 일반 사용자로 가입시켜 승격을 차단한다.
플래그는 CHALLENGE_SECRET 기반 정적 값(팀/매치 회전은 포털 그레이더의 팀키로 처리).
"""
import hashlib
import os
import secrets

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="WEB-011 Oil Corp Portal (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_WEB_011", "false").lower() == "true"


def static_flag() -> str:
    sig = hashlib.sha256(f"WEB-011:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{oil_corp_privesc_{sig}}}"


# 인메모리 사용자/세션(훈련용). {email: {password, name, is_admin}}, {token: email}
_USERS: dict[str, dict] = {}
_SESSIONS: dict[str, str] = {}


class RegisterRequest(BaseModel):
    email: str = Field(min_length=3, max_length=120)
    password: str = Field(min_length=6, max_length=200)
    name: str = Field(min_length=1, max_length=80)
    # 의도된 취약점 표면: 클라이언트가 권한 필드를 보낼 수 있다.
    is_admin: bool = False


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=120)
    password: str = Field(min_length=6, max_length=200)


@app.get("/health")
def health():
    return {"status": "ok", "patched": PATCHED, "service": "oil-corp-portal"}


@app.get("/api/version")
def version():
    return {"service": "한국석유공사 유가알림 포털", "api": "v1"}


@app.post("/api/auth/register", status_code=201)
def register(req: RegisterRequest):
    if req.email in _USERS:
        raise HTTPException(409, "이미 가입된 이메일")
    if PATCHED:
        # 방어: 클라이언트가 보낸 권한 필드를 신뢰하지 않는다. 가입은 항상 일반 사용자.
        is_admin = False
    else:
        # 취약: 클라이언트가 보낸 is_admin 을 그대로 계정 권한에 반영(mass assignment).
        is_admin = bool(req.is_admin)
    _USERS[req.email] = {
        "password": req.password, "name": req.name, "is_admin": is_admin,
    }
    return {"registered": True, "email": req.email, "is_admin": is_admin}


@app.post("/api/auth/login")
def login(req: LoginRequest):
    user = _USERS.get(req.email)
    if not user or user["password"] != req.password:
        raise HTTPException(401, "이메일 또는 비밀번호가 올바르지 않습니다")
    token = secrets.token_urlsafe(24)
    _SESSIONS[token] = req.email
    return {"access_token": token, "token_type": "bearer"}


def _current_user(authorization: str = Header(default="")) -> dict:
    token = authorization.removeprefix("Bearer ").strip()
    email = _SESSIONS.get(token)
    if not email or email not in _USERS:
        raise HTTPException(401, "인증이 필요합니다")
    return {"email": email, **_USERS[email]}


@app.get("/api/auth/me")
def me(user: dict = Depends(_current_user)):
    return {"email": user["email"], "name": user["name"], "is_admin": user["is_admin"]}


@app.get("/api/price/diesel")
def diesel_price():
    """일반 가입자도 볼 수 있는 유가 알림(정상 기능)."""
    return {"product": "diesel", "won_per_liter": 1587.4, "updated": "2025-11-01"}


@app.get("/api/admin/flag")
def admin_flag(user: dict = Depends(_current_user)):
    """관리자 전용 — 비상 대응 문서(플래그)."""
    if not user.get("is_admin"):
        raise HTTPException(403, "관리자 권한이 필요합니다")
    return {"emergency_response_token": static_flag()}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8111)
