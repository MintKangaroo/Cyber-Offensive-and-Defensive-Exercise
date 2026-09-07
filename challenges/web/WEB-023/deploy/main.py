"""WEB-023 배포용 서비스 — 한수원 원전 통합인증(JWT kid 경로 주입).

JWT 검증이 헤더의 kid(키 식별자)로 서명 키 파일을 로드하는데(keys/<kid>), kid 를 정규화하지
않아 경로 탐색이 가능하다. kid 를 예측 가능한 파일(예: /dev/null → 빈 키)로 지정하면 공격자가
그 키로 토큰을 위조할 수 있다(role=admin) → 관제 마스터 토큰(flag).

PATCH_WEB_023=true 면 kid 를 basename+허용목록으로 제한해 경로 탐색을 차단한다.
"""
import base64
import hashlib
import hmac
import json
import os
import time
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException

app = FastAPI(title="WEB-023 KHNP Auth (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_WEB_023", "false").lower() == "true"
KEYS_DIR = Path(os.environ.get("KEYS_DIR", "/app/keys"))
KEYS_DIR.mkdir(parents=True, exist_ok=True)
# 정상 서명 키(공격자 미상). 정상 토큰의 kid="primary".
(KEYS_DIR / "primary").write_bytes(os.urandom(32))
_ALLOWED_KIDS = {"primary"}


def static_flag() -> str:
    sig = hashlib.sha256(f"WEB-023:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{jwt_kid_inject_{sig}}}"


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64url_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _load_key(kid: str) -> bytes:
    if PATCHED:
        # 방어: basename + 허용목록
        kid = os.path.basename(kid)
        if kid not in _ALLOWED_KIDS:
            raise HTTPException(401, "허용되지 않은 kid")
        return (KEYS_DIR / kid).read_bytes()
    # 취약: kid 를 경로에 그대로 결합(경로 탐색 가능)
    p = KEYS_DIR / kid
    try:
        return Path(os.path.normpath(str(p))).read_bytes()
    except (FileNotFoundError, IsADirectoryError, PermissionError):
        raise HTTPException(401, "kid 키 로드 실패")


def _sign(payload: dict, kid: str) -> str:
    header = {"alg": "HS256", "typ": "JWT", "kid": kid}
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    key = _load_key(kid)
    sig = hmac.new(key, f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url(sig)}"


@app.get("/health")
def health():
    return {"status": "ok", "patched": PATCHED, "service": "khnp-auth"}


@app.get("/api/version")
def version():
    return {"protocol": "ad-http-v1", "service": "khnp-auth"}


@app.post("/api/auth/login")
def login():
    # 게스트(viewer) 토큰 — kid=primary
    return {"access_token": _sign(
        {"sub": "guest", "role": "viewer", "exp": int(time.time()) + 3600}, "primary")}


def _verify(authorization: str) -> dict:
    token = authorization.removeprefix("Bearer ").strip()
    if token.count(".") != 2:
        raise HTTPException(401, "토큰 형식 오류")
    h_b64, p_b64, sig_b64 = token.split(".")
    header = json.loads(_b64url_dec(h_b64))
    kid = str(header.get("kid", ""))
    key = _load_key(kid)                      # kid 로 키 로드(취약: 경로 탐색)
    expected = hmac.new(key, f"{h_b64}.{p_b64}".encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, _b64url_dec(sig_b64)):
        raise HTTPException(401, "서명 검증 실패")
    payload = json.loads(_b64url_dec(p_b64))
    if payload.get("exp", 1 << 62) < time.time():
        raise HTTPException(401, "만료")
    return payload


def _claims(authorization: str = Header(default="")) -> dict:
    return _verify(authorization)


@app.get("/api/reactor/status")
def reactor_status(claims: dict = Depends(_claims)):
    return {"core_temp_c": 315.2, "role": claims.get("role")}


@app.get("/api/admin/flag")
def admin_flag(claims: dict = Depends(_claims)):
    if claims.get("role") != "admin":
        raise HTTPException(403, "관리자 권한 필요")
    return {"reactor_master_token": static_flag()}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8126)
