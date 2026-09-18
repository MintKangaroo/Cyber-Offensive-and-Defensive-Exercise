"""CRY-018 배포용 서비스 — 국가 PKI 루트키 백업 RSA, p 상위비트 유출(Coppersmith 부분키 노출).

키 백업 시스템이 로그에 소수 p 의 상위 비트를 실수로 남긴다(부분키 노출). N 과 p 의 상위 비트가
알려지면 Coppersmith(미지 divisor mod 작은 근, Howgrave-Graham + LLL)로 p 의 하위 비트를 복구해
N 을 인수분해할 수 있다(하위 미지 비트 < N^(1/4) 이면 성립). 복구한 소인수를 제출하면 flag.

PATCH_CRY_018=true 면 유출 비트를 줄여(미지 비트 > N^(1/4)) Coppersmith 가 불가능해진다.
"""
import hashlib
import os
import random

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="CRY-018 PKI Root Key Backup RSA (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — RSA 키 시드는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_CRY_018", "false").lower() == "true"


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
    rnd = random.Random(hashlib.sha256(f"CRY-018:{tag}:{CHALLENGE_SECRET}".encode()).digest())
    while True:
        p = rnd.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(p):
            return p


P = _genprime(256, "p")
Q = _genprime(256, "q")
N = P * Q
E = 65537
# 유출된 상위 비트 수: 취약(미지 하위 110비트 < 256/4=64? — 256비트 p 의 N^(1/4)=128비트 → 미지<128 성립)
UNKNOWN_BITS = 110 if not PATCHED else 170  # 패치: 미지 170비트 > 128 → 복구 불가
P_HIGH = (P >> UNKNOWN_BITS) << UNKNOWN_BITS


def static_flag():
    sig = hashlib.sha256(f"CRY-018:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{coppersmith_partial_key_factoring_{sig}}}"


class RecoverReq(BaseModel):
    factor: str  # hex or decimal


@app.get("/")
def index():
    return {
        "service": "PKI root key backup RSA",
        "note": "키 백업 로그에 소수 p 의 상위 비트가 남았다. (TRAINING ONLY)",
        "endpoints": ["GET /api/leak", "POST /api/recover {factor}"],
        "patched": PATCHED,
    }


@app.get("/api/leak")
def leak():
    return {
        "n": hex(N),
        "e": E,
        "p_high": hex(P_HIGH),
        "unknown_bits": UNKNOWN_BITS,
        "note": "p = p_high + x, 0 <= x < 2^unknown_bits. 미지 x 가 N^(1/4) 미만이면 Coppersmith 로 복구 가능.",
    }


@app.post("/api/recover")
def recover(req: RecoverReq):
    raw = req.factor.strip()
    try:
        f = int(raw, 16) if raw.lower().startswith("0x") else int(raw)
    except ValueError:
        return {"ok": False, "detail": "factor must be integer"}
    if 1 < f < N and N % f == 0:
        return {"ok": True, "flag": static_flag()}
    return {"ok": False, "detail": "not a nontrivial factor of N"}
