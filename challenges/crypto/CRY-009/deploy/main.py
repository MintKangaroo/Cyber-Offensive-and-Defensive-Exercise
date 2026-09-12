"""CRY-009 배포용 서비스 — 재난경보 OTP 발급(MT19937 상태복구 예측).

일회용 토큰을 파이썬 기본 PRNG(MT19937)로 생성한다. 연속 624개 32비트 출력을 untemper 하면
내부 상태를 완전히 복구할 수 있어, 다음 관리자 OTP 를 예측할 수 있다. 배포된 624개로 다음
OTP 를 맞히면 flag.

PATCH_CRY_009=true 면 관리자 OTP 를 CSPRNG(secrets)로 발급해 예측을 막는다.
"""
import hashlib
import os
import random
import secrets

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="CRY-009 Disaster Alert OTP (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그/시드는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_CRY_009", "false").lower() == "true"


def static_flag() -> str:
    sig = hashlib.sha256(f"CRY-009:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{mt19937_state_recovery_{sig}}}"


# MT19937 시드는 시크릿에서 결정(재현 가능). 624개 노출 + 다음 1개(관리자 OTP).
_seed = int.from_bytes(hashlib.sha256(f"CRY-009:seed:{CHALLENGE_SECRET}".encode()).digest(), "big")
_rng = random.Random(_seed)
LEAKED = [_rng.getrandbits(32) for _ in range(624)]
if PATCHED:
    ADMIN_OTP = secrets.randbits(32)   # CSPRNG — 624개로 예측 불가
else:
    ADMIN_OTP = _rng.getrandbits(32)   # MT19937 다음 출력 — 예측 가능


class AdminReq(BaseModel):
    otp: int


@app.get("/")
def index():
    return {
        "service": "disaster alert OTP",
        "note": "일회용 토큰은 시스템 PRNG 로 발급됩니다. (TRAINING ONLY)",
        "endpoints": ["GET /api/tokens", "POST /api/admin {otp: int}"],
        "patched": PATCHED,
    }


@app.get("/api/tokens")
def tokens():
    return {"count": len(LEAKED), "tokens": LEAKED,
            "note": "발급된 연속 OTP 624개. 다음 관리자 OTP 를 예측해 /api/admin 에 제출하세요."}


@app.post("/api/admin")
def admin(req: AdminReq):
    if req.otp == ADMIN_OTP:
        return {"ok": True, "flag": static_flag()}
    return {"ok": False, "detail": "invalid OTP"}
