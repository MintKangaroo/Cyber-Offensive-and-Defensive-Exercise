"""CRY-016 배포용 서비스 — 원자로 명령 게이트웨이 RSA 저지수(e=3) stereotyped 메시지(Coppersmith).

게이트웨이가 원자로 명령을 RSA(e=3)로 암호화해 공개한다. 명령은 알려진 접두부(prefix)와 미지의
인증 토큰(하위 비트)으로 구성되며 접두부는 공개된다. e=3 이고 미지 부분이 작으면(|x0| < N^(1/3))
Coppersmith 의 작은 근 정리(Howgrave-Graham + LLL)로 개인키 없이 미지 토큰을 복구할 수 있다.
복구한 토큰을 제출하면 flag.

PATCH_CRY_016=true 면 e=65537 로 바꿔 미지 부분이 N^(1/e) 를 크게 초과해 Coppersmith 가 불가능해진다.
"""
import hashlib
import os
import random

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="CRY-016 Reactor Command Gateway RSA (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — RSA 키/토큰 시드는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_CRY_016", "false").lower() == "true"


def _is_prime(nn):
    if nn < 2:
        return False
    for pp in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if nn % pp == 0:
            return nn == pp
    d, r = nn - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, nn)
        if x in (1, nn - 1):
            continue
        for _ in range(r - 1):
            x = x * x % nn
            if x == nn - 1:
                break
        else:
            return False
    return True


def _genprime(bits, tag):
    rnd = random.Random(hashlib.sha256(f"CRY-016:{tag}:{CHALLENGE_SECRET}".encode()).digest())
    while True:
        # e=3 요건: p % 3 != 1 이어야 gcd(3, p-1)=1
        p = rnd.getrandbits(bits) | (1 << (bits - 1)) | 1
        if p % 3 != 1 and _is_prime(p):
            return p


P = _genprime(256, "p")
Q = _genprime(256, "q")
N = P * Q
E = 65537 if PATCHED else 3
K_UNKNOWN = 96  # 미지 토큰 비트수 (< N^(1/3) ≈ 170비트)

PREFIX = b"REACTOR-CMD:setpoint=full;override;auth="
_token_int = int.from_bytes(
    hashlib.sha256(f"CRY-016:token:{CHALLENGE_SECRET}".encode()).digest(), "big"
) % (1 << K_UNKNOWN)
TOKEN_HEX = f"{_token_int:024x}"  # 96비트 = 24 hex
_a = int.from_bytes(PREFIX, "big") << K_UNKNOWN
_m = _a + _token_int
C = pow(_m, E, N)


def static_flag():
    sig = hashlib.sha256(f"CRY-016:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{coppersmith_stereotyped_rsa_{sig}}}"


class RecoverReq(BaseModel):
    token: str  # hex


@app.get("/")
def index():
    return {
        "service": "reactor command gateway RSA",
        "note": "원자로 명령을 RSA 로 암호화해 공개. 접두부는 알려져 있음. (TRAINING ONLY)",
        "endpoints": ["GET /api/message", "POST /api/recover {token}"],
        "patched": PATCHED,
    }


@app.get("/api/message")
def message():
    return {
        "n": hex(N),
        "e": E,
        "c": hex(C),
        "known_prefix": PREFIX.decode(),
        "unknown_bits": K_UNKNOWN,
        "hint": "message = int.from_bytes(prefix) << unknown_bits | token; token 하위 96비트 미지",
    }


@app.post("/api/recover")
def recover(req: RecoverReq):
    raw = req.token.strip().lower()
    if raw.startswith("0x"):
        raw = raw[2:]
    try:
        sub = int(raw, 16)
    except ValueError:
        return {"ok": False, "detail": "token must be hex"}
    if sub == _token_int:
        return {"ok": True, "flag": static_flag()}
    return {"ok": False, "detail": "incorrect token"}
