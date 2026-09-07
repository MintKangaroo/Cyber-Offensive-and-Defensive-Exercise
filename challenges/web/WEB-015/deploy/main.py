"""WEB-015 배포용 서비스 — 전력거래소(KPX) 급전 관제 API(JWT 알고리즘 혼동 RS256→HS256).

관제 API 는 RS256(비대칭)으로 서명한 JWT 를 발급하고 공개키를 /api/auth/pubkey 로 공개한다.
검증 로직이 헤더의 alg 를 신뢰해 alg=HS256 이면 '공개키를 HMAC 비밀키로' 검증한다(순진한 수동
검증 — 라이브러리 가드를 우회한 고전 취약 패턴). 공개키는 누구나 알 수 있으므로 공격자가 공개키를
HMAC 키로 HS256 admin 토큰을 위조하면 통과한다.

PATCH_WEB_015=true 면 alg 를 RS256 으로 고정(HS256 거부)해 혼동 공격을 차단한다.
"""
import base64
import hashlib
import hmac
import json
import os
import time

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI, Header, HTTPException

app = FastAPI(title="WEB-015 KPX Dispatch API (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_WEB_015", "false").lower() == "true"

_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PRIV_PEM = _key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
).decode()
PUB_PEM = _key.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
).decode()


def static_flag() -> str:
    sig = hashlib.sha256(f"WEB-015:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{kpx_jwt_algconf_{sig}}}"


def _b64url_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


@app.get("/health")
def health():
    return {"status": "ok", "patched": PATCHED, "service": "kpx-dispatch"}


@app.get("/api/version")
def version():
    return {"protocol": "ad-http-v1", "service": "kpx-dispatch"}


@app.get("/api/auth/pubkey")
def pubkey():
    return {"alg": "RS256", "public_key": PUB_PEM}


@app.post("/api/auth/login")
def login():
    token = jwt.encode(
        {"sub": "guest", "role": "viewer", "iat": int(time.time()),
         "exp": int(time.time()) + 3600},
        PRIV_PEM, algorithm="RS256",
    )
    return {"access_token": token, "role": "viewer"}


def _verify(authorization: str) -> dict:
    token = authorization.removeprefix("Bearer ").strip()
    if not token or token.count(".") != 2:
        raise HTTPException(401, "토큰 필요")
    h_b64, p_b64, sig_b64 = token.split(".")
    try:
        header = json.loads(_b64url_dec(h_b64))
    except Exception:
        raise HTTPException(401, "헤더 파싱 실패")
    alg = header.get("alg")
    if alg == "RS256":
        try:
            return jwt.decode(token, PUB_PEM, algorithms=["RS256"])
        except jwt.InvalidTokenError:
            raise HTTPException(401, "RS256 검증 실패")
    if alg == "HS256" and not PATCHED:
        # 취약: alg 를 신뢰해 '공개키를 HMAC 비밀키로' 수동 검증(고전 RS/HS 혼동)
        expected = hmac.new(PUB_PEM.encode(), f"{h_b64}.{p_b64}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64url_dec(sig_b64)):
            raise HTTPException(401, "HS256 검증 실패")
        payload = json.loads(_b64url_dec(p_b64))
        if payload.get("exp", 1 << 62) < time.time():
            raise HTTPException(401, "만료")
        return payload
    raise HTTPException(401, f"허용되지 않은 alg: {alg}")


def _claims(authorization: str = Header(default="")) -> dict:
    return _verify(authorization)


@app.get("/api/dispatch/status")
def dispatch_status(claims: dict = Depends(_claims)):
    return {"grid_freq_hz": 60.01, "reserve_mw": 8200, "role": claims.get("role")}


@app.get("/api/admin/flag")
def admin_flag(claims: dict = Depends(_claims)):
    if claims.get("role") != "admin":
        raise HTTPException(403, "관리자(admin) 권한 필요")
    return {"dispatch_master_token": static_flag()}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8115)
