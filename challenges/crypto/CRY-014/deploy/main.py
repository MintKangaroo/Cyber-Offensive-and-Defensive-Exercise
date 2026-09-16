"""CRY-014 배포용 서비스 — 원전 계측 게이트웨이 RSA PKCS#1 v1.5 패딩 오라클(Bleichenbacher).

게이트웨이가 세션 토큰을 RSA PKCS#1 v1.5 로 감싸(c0) 공개하고, 임의 암호문을 복호했을 때 패딩이
유효한지(00 02 ...) 여부를 응답한다. 이 패딩 오라클로 Bleichenbacher(1998) 적응적 선택암호문
공격을 수행하면 개인키 없이 c0 의 평문(세션 토큰)을 복구할 수 있다. 복구한 토큰을 제출하면 flag.

PATCH_CRY_014=true 면 /api/unwrap 이 패딩 유효성을 노출하지 않아(항상 동일 응답) 오라클이 사라져
Bleichenbacher 가 불가능해진다.
"""
import hashlib
import os
import random

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="CRY-014 Instrument Gateway RSA Oracle (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — RSA 키/토큰 시드는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_CRY_014", "false").lower() == "true"


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
    rnd = random.Random(hashlib.sha256(f"CRY-014:{tag}:{CHALLENGE_SECRET}".encode()).digest())
    while True:
        p = rnd.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(p):
            return p


P = _genprime(256, "p")
Q = _genprime(256, "q")
N = P * Q
E = 65537
D = pow(E, -1, (P - 1) * (Q - 1))
K = (N.bit_length() + 7) // 8

# 복구 대상 세션 토큰(개인키 없이 Bleichenbacher 로 복구해야 함)
TOKEN = ("UNLOCK-" + hashlib.sha256(f"CRY-014:token:{CHALLENGE_SECRET}".encode()).hexdigest()[:12]).encode()


def _pkcs_pad(msg):
    rnd = random.Random(hashlib.sha256(f"CRY-014:pad:{CHALLENGE_SECRET}".encode()).digest())
    ps = bytearray()
    while len(ps) < K - 3 - len(msg):
        b = rnd.randint(1, 255)
        ps.append(b)
    return b"\x00\x02" + bytes(ps) + b"\x00" + msg


C0 = pow(int.from_bytes(_pkcs_pad(TOKEN), "big"), E, N)


def static_flag():
    sig = hashlib.sha256(f"CRY-014:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{bleichenbacher_padding_oracle_{sig}}}"


class UnwrapReq(BaseModel):
    c: str  # hex 암호문


class RecoverReq(BaseModel):
    token: str


@app.get("/")
def index():
    return {
        "service": "instrument gateway RSA session unwrap",
        "scheme": "RSA PKCS#1 v1.5",
        "note": "세션 토큰을 RSA 로 감싸 공개. 복호 시 패딩 유효성을 응답. (TRAINING ONLY)",
        "endpoints": ["GET /api/token", "POST /api/unwrap {c}", "POST /api/recover {token}"],
        "patched": PATCHED,
    }


@app.get("/api/token")
def token():
    return {"n": hex(N), "e": E, "c0": hex(C0), "k": K}


@app.post("/api/unwrap")
def unwrap(req: UnwrapReq):
    try:
        c = int(req.c, 16) % N
    except ValueError:
        return {"padding_ok": False, "detail": "c must be hex"}
    m = pow(c, D, N).to_bytes(K, "big")
    if PATCHED:
        # 패치: 패딩 유효성을 노출하지 않음(오라클 제거). 항상 동일 응답.
        return {"status": "processed"}
    # 취약: PKCS#1 v1.5 패딩(00 02) 유효성을 그대로 노출 → Bleichenbacher 오라클.
    return {"padding_ok": m[0] == 0 and m[1] == 2}


@app.post("/api/recover")
def recover(req: RecoverReq):
    if req.token.strip().encode() == TOKEN:
        return {"ok": True, "flag": static_flag()}
    return {"ok": False, "detail": "incorrect token"}
