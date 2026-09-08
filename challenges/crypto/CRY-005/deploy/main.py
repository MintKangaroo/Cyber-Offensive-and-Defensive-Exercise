"""CRY-005 배포용 서비스 — 정부 전자서명 감사시스템(DSA 논스 재사용 → 개인키 복구).

감사 레코드 두 건을 '같은 논스 k'로 DSA 서명해 배포한다(논스 재사용 버그). 같은 k 면 r 이
동일하므로:
    k = (H1 - H2) · (s1 - s2)^{-1} mod q
    x = (s1·k - H1) · r^{-1} mod q
로 서명 개인키 x 를 복구할 수 있다. 복구한 x 로 관리자 승인 메시지를 서명해 제출하면 서버가
공개키 y 로 검증하고 flag 를 내준다.

PATCH_CRY_005=true 면 서명마다 임의 논스를 써서(재사용 제거) 개인키 복구를 막는다.
"""
import hashlib
import os

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="CRY-005 Gov e-Signature Audit (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그/키 시드는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_CRY_005", "false").lower() == "true"
GRANT_MSG = b"ADMIN-OVERRIDE-GRANT"


def static_flag() -> str:
    sig = hashlib.sha256(f"CRY-005:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{dsa_nonce_reuse_{sig}}}"


def _seeded_int(tag: str, bits: int) -> int:
    out = b""
    counter = 0
    while len(out) * 8 < bits:
        out += hashlib.sha256(f"{tag}:{counter}:{CHALLENGE_SECRET}".encode()).digest()
        counter += 1
    return int.from_bytes(out, "big") >> (len(out) * 8 - bits)


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


def _gen_dsa():
    q = _next_prime(_seeded_int("q", 160) | (1 << 159))
    # p = k*q + 1 (512비트, q | p-1). 논스 재사용 공격은 p 크기와 무관 → 기동 속도 위해 512비트.
    k0 = _seeded_int("pk", 352) | (1 << 351)
    k0 -= k0 % 2  # 짝수 → p 홀수
    kk = k0
    while True:
        p = kk * q + 1  # p ≈ 511비트, q | p-1
        if _is_prime(p):
            break
        kk += 2
    h = 2
    while True:
        g = pow(h, (p - 1) // q, p)
        if g > 1:
            break
        h += 1
    x = (_seeded_int("x", 160) % (q - 1)) + 1
    y = pow(g, x, p)
    return p, q, g, x, y


_P, _Q, _G, _X, _Y = _gen_dsa()


def _hm(m: bytes) -> int:
    return int.from_bytes(hashlib.sha1(m).digest(), "big") % _Q


def _sign(m: bytes, k: int):
    r = pow(_G, k, _P) % _Q
    s = (pow(k, -1, _Q) * (_hm(m) + _X * r)) % _Q
    return r, s


def _verify(m: bytes, r: int, s: int) -> bool:
    if not (0 < r < _Q and 0 < s < _Q):
        return False
    w = pow(s, -1, _Q)
    u1 = (_hm(m) * w) % _Q
    u2 = (r * w) % _Q
    v = ((pow(_G, u1, _P) * pow(_Y, u2, _P)) % _P) % _Q
    return v == r


class Sig(BaseModel):
    r: str
    s: str


@app.get("/health")
def health():
    return {"status": "ok", "patched": PATCHED, "service": "gov-esign-audit"}


@app.get("/api/version")
def version():
    return {"protocol": "ad-http-v1", "service": "gov-esign-audit"}


@app.get("/api/params")
def params():
    return {"p": format(_P, "x"), "q": format(_Q, "x"), "g": format(_G, "x"), "y": format(_Y, "x")}


@app.get("/api/audit/signatures")
def signatures():
    """감사 레코드 2건의 DSA 서명. 취약: 두 서명이 같은 논스 k 를 재사용(r 동일)."""
    m1 = b"AUDIT LOG #4471: valve calibration approved"
    m2 = b"AUDIT LOG #4472: turbine schedule approved"
    if PATCHED:
        k1 = (_seeded_int("nonce-rand1", 159) % (_Q - 1)) + 1
        k2 = (_seeded_int("nonce-rand2", 159) % (_Q - 1)) + 1
    else:
        k = (_seeded_int("nonce", 159) % (_Q - 1)) + 1  # 재사용
        k1 = k2 = k
    r1, s1 = _sign(m1, k1)
    r2, s2 = _sign(m2, k2)
    return {
        "records": [
            {"message": m1.decode(), "r": format(r1, "x"), "s": format(s1, "x")},
            {"message": m2.decode(), "r": format(r2, "x"), "s": format(s2, "x")},
        ]
    }


@app.post("/api/admin/grant")
def grant(sig: Sig):
    """관리자 승인 메시지에 대한 유효 서명을 제출하면 flag 를 내준다(공개키 y 로 검증)."""
    try:
        r = int(sig.r, 16)
        s = int(sig.s, 16)
    except ValueError:
        return {"granted": False, "detail": "invalid hex"}
    if _verify(GRANT_MSG, r, s):
        return {"granted": True, "flag": static_flag()}
    return {"granted": False, "detail": "signature verification failed"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8137)
