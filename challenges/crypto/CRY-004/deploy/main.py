"""CRY-004 배포용 서비스 — 원전 계측문서 게이트웨이(RSA 공통 모듈러스 공격).

두 부서(A/B)가 '같은 평문(계측문서=flag)'을 '같은 모듈러스 N'에 서로 다른 공개지수 e1, e2
(gcd(e1,e2)=1)로 암호화해 배포한다. 공통 모듈러스 + 서로소 지수 + 동일 평문이면 확장
유클리드로 u·e1 + v·e2 = 1 을 구해 m = c1^u · c2^v mod N 으로 평문을 개인키 없이 복구할 수 있다.

PATCH_CRY_004=true 면 부서마다 서로 다른 모듈러스를 써서(공통 모듈러스 제거) 공격을 무력화한다.
"""
import hashlib
import os

from fastapi import FastAPI

app = FastAPI(title="CRY-004 Nuclear Plant Metering Gateway (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그/키 시드는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_CRY_004", "false").lower() == "true"
E1 = 65537
E2 = 65539  # gcd(E1,E2)=1


def static_flag() -> str:
    sig = hashlib.sha256(f"CRY-004:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{rsa_common_modulus_{sig}}}"


def _seeded_int(tag: str, bits: int) -> int:
    out = b""
    counter = 0
    while len(out) * 8 < bits:
        out += hashlib.sha256(f"{tag}:{counter}:{CHALLENGE_SECRET}".encode()).digest()
        counter += 1
    return int.from_bytes(out, "big") >> (len(out) * 8 - bits)


def _is_probable_prime(n: int) -> bool:
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
    while not _is_probable_prime(n):
        n += 2
    return n


def _modulus(tag: str) -> int:
    p = _next_prime(_seeded_int(f"{tag}-p", 512) | (1 << 511))
    q = _next_prime(_seeded_int(f"{tag}-q", 512) | (1 << 511))
    return p * q


_N = _modulus("shared")
_N_B = _N if not PATCHED else _modulus("deptB")  # 패치: 부서 B 는 다른 모듈러스

# 평문(계측문서 = flag). m < min(N) 보장(문서 짧음, N ~1024bit).
_M = int.from_bytes(
    (
        "KHNP METERING DOC / CLASSIFIED override_token="
        + static_flag()
    ).encode(),
    "big",
)


@app.get("/health")
def health():
    return {"status": "ok", "patched": PATCHED, "service": "khnp-metering-gateway"}


@app.get("/api/version")
def version():
    return {"protocol": "ad-http-v1", "service": "khnp-metering-gateway"}


@app.get("/api/pubkeys")
def pubkeys():
    """부서 A/B 공개키. 취약: 두 부서가 같은 모듈러스 N 을 공유(지수만 다름)."""
    return {
        "N_dept_a": format(_N, "x"),
        "e_dept_a": E1,
        "N_dept_b": format(_N_B, "x"),
        "e_dept_b": E2,
    }


@app.get("/api/dept/a/ciphertext")
def ct_a():
    """부서 A 암호문 c1 = m^e1 mod N."""
    return {"ciphertext": format(pow(_M, E1, _N), "x"), "e": E1}


@app.get("/api/dept/b/ciphertext")
def ct_b():
    """부서 B 암호문 c2 = m^e2 mod N (동일 평문·동일 모듈러스)."""
    return {"ciphertext": format(pow(_M, E2, _N_B), "x"), "e": E2}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8136)
