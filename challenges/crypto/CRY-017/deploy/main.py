"""CRY-017 배포용 서비스 — 전력거래 봉인입찰(Paillier) 준동형 가변성(malleability) 위조.

전력거래소가 Paillier 로 암호화된 봉인입찰을 받는다. 서버는 관리자 크레딧 V 의 암호문 c_V=E(V) 를
공개한다. /api/redeem 은 제출된 암호문을 복호해 평문이 V+GRANT_DELTA 이면 flag 를 준다. Paillier 는
준동형(가변)이라 개인키·V 를 몰라도 c_V · g^GRANT_DELTA = E(V+GRANT_DELTA) 를 만들어 제출할 수 있다.
(무결성 없는 준동형 암호의 가변성 악용)

PATCH_CRY_017=true 면 redeem 이 서버 HMAC 태그가 붙은 암호문만 수락해(서버만 태그 생성 가능) 위조
암호문을 거부한다.
"""
import hashlib
import hmac
import os
import random

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="CRY-017 Sealed-bid Paillier Auction (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — Paillier 키/크레딧 시드는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_CRY_017", "false").lower() == "true"
GRANT_DELTA = 0x1337c0de


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
    rnd = random.Random(hashlib.sha256(f"CRY-017:{tag}:{CHALLENGE_SECRET}".encode()).digest())
    while True:
        p = rnd.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(p):
            return p


P = _genprime(512, "p")
Q = _genprime(512, "q")
N = P * Q
N2 = N * N
G = N + 1  # 표준 Paillier 생성원


def _gcd(a, b):
    while b:
        a, b = b, a % b
    return a


LAM = (P - 1) * (Q - 1) // _gcd(P - 1, Q - 1)
_MU = pow((pow(G, LAM, N2) - 1) // N % N, -1, N)

# 관리자 크레딧 V (비밀). r 무작위로 암호화.
V = int.from_bytes(hashlib.sha256(f"CRY-017:V:{CHALLENGE_SECRET}".encode()).digest(), "big") % N
_rand = random.Random(hashlib.sha256(f"CRY-017:r:{CHALLENGE_SECRET}".encode()).digest())
_r = _rand.randrange(1, N)
C_V = (pow(G, V, N2) * pow(_r, N, N2)) % N2

_TAG_KEY = hashlib.sha256(f"CRY-017:tag:{CHALLENGE_SECRET}".encode()).digest()


def _decrypt(c):
    u = pow(c, LAM, N2)
    l = (u - 1) // N
    return (l * _MU) % N


def _tag(c):
    return hmac.new(_TAG_KEY, str(c % N2).encode(), hashlib.sha256).hexdigest()


def static_flag():
    sig = hashlib.sha256(f"CRY-017:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{paillier_homomorphic_malleability_{sig}}}"


class RedeemReq(BaseModel):
    c: str            # hex 암호문
    tag: str = ""     # 패치 모드에서 필요한 서버 HMAC 태그


@app.get("/")
def index():
    return {
        "service": "sealed-bid Paillier auction",
        "note": "관리자 크레딧 암호문 c_V 공개. redeem 이 V+delta 를 복호하면 flag. (TRAINING ONLY)",
        "endpoints": ["GET /api/params", "POST /api/redeem {c,tag?}"],
        "patched": PATCHED,
    }


@app.get("/api/params")
def params():
    return {
        "n": hex(N),
        "g": hex(G),
        "c_admin_credit": hex(C_V),
        "grant_delta": hex(GRANT_DELTA),
        "note": "redeem 이 복호값 == V + grant_delta 이면 flag. Paillier: E(a)·E(b)=E(a+b), E(m)·g^k=E(m+k).",
    }


@app.post("/api/redeem")
def redeem(req: RedeemReq):
    try:
        c = int(req.c, 16) % N2
    except ValueError:
        return {"ok": False, "detail": "c must be hex"}
    if PATCHED:
        # 무결성: 서버가 발급한 태그가 붙은 암호문만 수락 → 위조(가변) 암호문 거부.
        if not hmac.compare_digest(req.tag, _tag(c)):
            return {"ok": False, "detail": "missing/invalid integrity tag (forged ciphertext rejected)"}
    m = _decrypt(c)
    if m == (V + GRANT_DELTA) % N:
        return {"ok": True, "flag": static_flag()}
    return {"ok": False, "detail": "decrypted plaintext does not grant access"}
