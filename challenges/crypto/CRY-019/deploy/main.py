"""CRY-019 배포용 서비스 — 스마트그리드 단말 대량발급 RSA, 약한 RNG 공유 소수(배치 GCD).

수만 대의 스마트그리드 단말이 부팅 시 엔트로피가 부족한 RNG 로 RSA 키를 생성해, 서로 다른 두 단말의
공개 모듈러스가 소수 하나를 공유한다. 공개된 여러 모듈러스에 대해 쌍별 GCD 를 구하면 공유 소수가
드러나 두 키가 즉시 인수분해된다(Mining your Ps and Qs, 2012). 취약 키로 암호화된 토큰을 복호해
제출하면 flag.

PATCH_CRY_019=true 면 모든 소수를 독립 생성해 공유 소수가 사라져 배치 GCD 가 무력화된다.
"""
import hashlib
import math
import os
import random

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="CRY-019 Smart-grid Bulk RSA Keygen (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — RSA 키 시드는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_CRY_019", "false").lower() == "true"
E = 65537
NUM_DEVICES = 8


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


def _prime(rnd, bits):
    while True:
        p = rnd.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(p):
            return p


def _rng(tag):
    return random.Random(hashlib.sha256(f"CRY-019:{tag}:{CHALLENGE_SECRET}".encode()).digest())


# 약한 RNG: 단말 2와 5 가 같은 소수 p_shared 를 공유(엔트로피 부족 시뮬레이션).
_shared = _prime(_rng("shared"), 512)
MODULI = []
KEYS = []  # (p,q) 내부 보관(플래그 복호용)
for i in range(NUM_DEVICES):
    if not PATCHED and i == 2:
        p = _shared
        q = _prime(_rng(f"q{i}"), 512)
    elif not PATCHED and i == 5:
        p = _shared
        q = _prime(_rng(f"q{i}"), 512)
    else:
        p = _prime(_rng(f"p{i}"), 512)
        q = _prime(_rng(f"q{i}"), 512)
    MODULI.append(p * q)
    KEYS.append((p, q))

# 취약 단말(2번)의 공개키로 세션 토큰 암호화.
TOKEN = ("GRIDKEY-" + hashlib.sha256(f"CRY-019:token:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]).encode()
_vuln_idx = 2
_Nv = MODULI[_vuln_idx]
C = pow(int.from_bytes(TOKEN, "big"), E, _Nv)


def static_flag():
    sig = hashlib.sha256(f"CRY-019:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{batch_gcd_shared_prime_{sig}}}"


class RecoverReq(BaseModel):
    token: str


@app.get("/")
def index():
    return {
        "service": "smart-grid bulk RSA keygen",
        "note": "여러 단말의 공개 모듈러스를 공개. 취약 단말의 토큰을 복호해 제출. (TRAINING ONLY)",
        "endpoints": ["GET /api/devices", "POST /api/recover {token}"],
        "patched": PATCHED,
    }


@app.get("/api/devices")
def devices():
    return {
        "e": E,
        "moduli": [hex(n) for n in MODULI],
        "target_device": _vuln_idx,
        "ciphertext": hex(C),
        "note": "target_device 의 모듈러스는 다른 단말과 소수를 공유한다. 토큰을 복호해 제출.",
    }


@app.post("/api/recover")
def recover(req: RecoverReq):
    if req.token.strip().encode() == TOKEN:
        return {"ok": True, "flag": static_flag()}
    return {"ok": False, "detail": "incorrect token"}
