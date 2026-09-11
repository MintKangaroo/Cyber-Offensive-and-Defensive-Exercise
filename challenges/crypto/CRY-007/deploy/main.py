"""CRY-007 배포용 서비스 — 스마트미터 펌웨어 서명(RSA 작은 d, Wiener 공격).

개인지수 d 를 작게 잡아(d < N^0.25/3) 검증을 빠르게 하려다 Wiener 공격에 노출된다. 공개키
(N,e)만으로 e/N 연분수 수렴근사로 d 를 복구할 수 있다. 서버는 (N,e)로 암호화한 관리자 세션
토큰 c = token^e mod N 을 배포하고, 복구한 d 로 복호한 token 을 제출하면 flag 를 낸다.

PATCH_CRY_007=true 면 표준 e=65537·정상 크기 d 로 재발급해 Wiener 조건을 제거한다.
"""
import hashlib
import os

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="CRY-007 Smart Meter Firmware Signing (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그/키 시드는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_CRY_007", "false").lower() == "true"


def static_flag() -> str:
    sig = hashlib.sha256(f"CRY-007:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{rsa_wiener_small_d_{sig}}}"


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


def _gen_key():
    p = _next_prime(_seeded_int("p", 512))
    q = _next_prime(_seeded_int("q", 512))
    n = p * q
    phi = (p - 1) * (q - 1)
    if PATCHED:
        e = 65537
        d = pow(e, -1, phi)
        return n, e, d
    # 취약: 작은 d(Wiener 조건 d < N^0.25/3). d 를 홀수·phi 서로소로 선택 후 e=d^{-1} mod phi.
    bound = int(pow(n, 0.25)) // 3
    d = _seeded_int("d", 230) % bound | 1
    while _gcd(d, phi) != 1:
        d += 2
    e = pow(d, -1, phi)
    return n, e, d


def _gcd(a, b):
    while b:
        a, b = b, a % b
    return a


N, E, D = _gen_key()
# 관리자 세션 토큰(고정, 시크릿 유도). (N,E)로 암호화해 배포.
TOKEN_INT = int.from_bytes(hashlib.sha256(f"CRY-007:token:{CHALLENGE_SECRET}".encode()).digest(), "big")
CIPHERTEXT = pow(TOKEN_INT, E, N)


class AdminReq(BaseModel):
    token: str  # hex of decrypted token integer


@app.get("/")
def index():
    return {
        "service": "smart meter firmware signing",
        "note": "검증 속도를 위해 작은 개인지수를 씁니다. (TRAINING ONLY)",
        "endpoints": ["GET /api/pubkey", "GET /api/ciphertext", "POST /api/admin {token: hex}"],
        "patched": PATCHED,
    }


@app.get("/api/pubkey")
def pubkey():
    return {"N": hex(N), "e": hex(E)}


@app.get("/api/ciphertext")
def ciphertext():
    return {"c": hex(CIPHERTEXT), "note": "관리자 세션 토큰을 (N,e)로 암호화한 값"}


@app.post("/api/admin")
def admin(req: AdminReq):
    try:
        submitted = int(req.token, 16)
    except ValueError:
        return {"ok": False, "detail": "token must be hex integer"}
    if submitted == TOKEN_INT:
        return {"ok": True, "flag": static_flag()}
    return {"ok": False, "detail": "invalid admin token"}
