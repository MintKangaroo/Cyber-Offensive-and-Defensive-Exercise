"""CRY-010 배포용 서비스 — 국가 CCTV 관제 키 배포(RSA Håstad 브로드캐스트, e=3).

같은 관리자 키(평문)를 e=3 으로 서로 다른 세 모듈러스에 암호화해 배포한다. e=3·수신자 3명이면
Håstad 브로드캐스트: CRT 로 합치면 m^3 (mod N1 N2 N3), m 이 작아 m^3 < 곱 이면 정수 세제곱근이
평문이다. 복구한 관리자 키를 제출하면 flag.

PATCH_CRY_010=true 면 e=65537 로 키워 저지수 브로드캐스트 공격을 무력화한다.
"""
import hashlib
import os

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="CRY-010 National CCTV Key Broadcast (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그/키 시드는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_CRY_010", "false").lower() == "true"
E = 65537 if PATCHED else 3


def static_flag() -> str:
    sig = hashlib.sha256(f"CRY-010:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{rsa_hastad_broadcast_{sig}}}"


def _seeded_int(tag: str, bits: int) -> int:
    out = b""
    counter = 0
    while len(out) * 8 < bits:
        out += hashlib.sha256(f"{tag}:{counter}:{CHALLENGE_SECRET}".encode()).digest()
        counter += 1
    return (int.from_bytes(out, "big") >> (len(out) * 8 - bits)) | (1 << (bits - 1)) | 1


def _is_prime(n: int) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(tag: str) -> int:
    # e=3 과 서로소인 소수 필요(p-1, q-1 이 3 으로 나눠지지 않게).
    n = _seeded_int(tag, 512) | 1
    while not (_is_prime(n) and (n - 1) % 3 != 0):
        n += 2
    return n


# 서로 다른 세 기관의 모듈러스(각 512비트 소수 2개 → ~1024비트 N). 같은 평문.
def _modulus(i: int) -> int:
    return _prime(f"p{i}") * _prime(f"q{i}")


MODULI = [_modulus(1), _modulus(2), _modulus(3)]
# 관리자 키(평문, 256비트) — 모든 N 보다 작다.
TOKEN_INT = int.from_bytes(hashlib.sha256(f"CRY-010:token:{CHALLENGE_SECRET}".encode()).digest(), "big")
BROADCAST = [{"N": hex(n), "e": E, "c": hex(pow(TOKEN_INT, E, n))} for n in MODULI]


class AdminReq(BaseModel):
    token: str  # hex


@app.get("/")
def index():
    return {
        "service": "national CCTV key broadcast",
        "note": "관리자 키를 e=3 으로 세 기관에 브로드캐스트합니다. (TRAINING ONLY)",
        "endpoints": ["GET /api/broadcast", "POST /api/admin {token: hex}"],
        "patched": PATCHED,
    }


@app.get("/api/broadcast")
def broadcast():
    return {"recipients": BROADCAST}


@app.post("/api/admin")
def admin(req: AdminReq):
    try:
        submitted = int(req.token, 16)
    except ValueError:
        return {"ok": False, "detail": "token must be hex integer"}
    if submitted == TOKEN_INT:
        return {"ok": True, "flag": static_flag()}
    return {"ok": False, "detail": "invalid admin key"}
