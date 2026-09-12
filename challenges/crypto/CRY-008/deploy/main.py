"""CRY-008 배포용 서비스 — 중앙은행 결제 HSM(RSA LSB 패리티 오라클).

RSA 복호 결과의 최하위 비트를 상태로 흘린다(LSB 오라클). RSA 준동형으로 c·2^e mod N 의 복호는
2m mod N 이고, LSB 는 2m 이 N 을 넘겼는지를 알려주므로 이분탐색으로 m 전체를 복구할 수 있다.
서버가 (N,e)로 암호화한 관리자 결제 토큰을 복구해 제출하면 flag.

PATCH_CRY_008=true 면 오라클이 패리티를 반환하지 않아(복호 부산물 미노출) 복구를 막는다.
"""
import hashlib
import os

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="CRY-008 Central Bank Payment HSM (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그/키 시드는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_CRY_008", "false").lower() == "true"


def static_flag() -> str:
    sig = hashlib.sha256(f"CRY-008:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{rsa_lsb_parity_oracle_{sig}}}"


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


def _next_prime(start: int) -> int:
    n = start | 1
    while not _is_prime(n):
        n += 2
    return n


# 512비트 N(256비트 소수 2개) — 오라클 이분탐색 데모에 충분.
P = _next_prime(_seeded_int("p", 256))
Q = _next_prime(_seeded_int("q", 256))
N = P * Q
PHI = (P - 1) * (Q - 1)
E = 65537
D = pow(E, -1, PHI)
TOKEN_INT = int.from_bytes(hashlib.sha256(f"CRY-008:token:{CHALLENGE_SECRET}".encode()).digest(), "big") % N
CIPHERTEXT = pow(TOKEN_INT, E, N)


class CtReq(BaseModel):
    c: str  # hex


class AdminReq(BaseModel):
    token: str  # hex


@app.get("/")
def index():
    return {
        "service": "central bank payment HSM",
        "note": "복호 상태 코드에 LSB 가 포함됩니다. (TRAINING ONLY)",
        "endpoints": ["GET /api/pubkey", "GET /api/ciphertext", "POST /api/oracle {c: hex}", "POST /api/admin {token: hex}"],
        "patched": PATCHED,
    }


@app.get("/api/pubkey")
def pubkey():
    return {"N": hex(N), "e": hex(E)}


@app.get("/api/ciphertext")
def ciphertext():
    return {"c": hex(CIPHERTEXT), "note": "관리자 결제 토큰을 (N,e)로 암호화한 값"}


@app.post("/api/oracle")
def oracle(req: CtReq):
    try:
        c = int(req.c, 16) % N
    except ValueError:
        return {"ok": False, "detail": "c must be hex"}
    if PATCHED:
        # 복호 부산물(패리티) 미노출 — 유효성만 알린다.
        return {"ok": True, "detail": "processed"}
    m = pow(c, D, N)
    return {"ok": True, "lsb": m & 1}


@app.post("/api/admin")
def admin(req: AdminReq):
    try:
        submitted = int(req.token, 16)
    except ValueError:
        return {"ok": False, "detail": "token must be hex integer"}
    if submitted == TOKEN_INT:
        return {"ok": True, "flag": static_flag()}
    return {"ok": False, "detail": "invalid admin token"}
