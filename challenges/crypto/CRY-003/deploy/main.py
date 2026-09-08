"""CRY-003 배포용 서비스 — LNG 터미널 문서 금고(취약 RSA 키 생성 → AES 문서 복호).

CCE 본선 write-up 참고(구조적 모듈러스 인수분해). 소수를 p = 2^512 + a, q = 2^512 + b 로
생성하는데, a·b 가 작아 모듈러스에 대수적 구조가 남는다:

    N = (2^512 + a)(2^512 + b) = 2^1024 + (a+b)·2^512 + a·b

a·b < 2^512 이므로 (N - 2^1024) 를 2^512 로 나눈 몫이 S=a+b, 나머지가 P=a·b 이다.
t^2 - S·t + P = 0 을 풀면 a, b 를 얻어 p, q 로 N 을 인수분해 → d 복구 → RSA 로 감싼 AES 키
복구 → AES-CBC 로 봉인된 LNG 계량 문서(flag) 복호.

PATCH_CRY_003=true 면 서로 독립적인 임의 대형 소수를 써서 구조를 제거(인수분해 불가).
"""
import hashlib
import os

from fastapi import FastAPI
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = FastAPI(title="CRY-003 LNG Terminal Document Vault (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그/키 시드는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_CRY_003", "false").lower() == "true"
E = 65537


def static_flag() -> str:
    sig = hashlib.sha256(f"CRY-003:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{rsa_structured_modulus_{sig}}}"


def _seeded_int(tag: str, bits: int) -> int:
    """CHALLENGE_SECRET 로 결정적 시드값 생성(기동마다 동일 → 플래그/키 안정)."""
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
    d = n - 1
    r = 0
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
    n = start | 1  # 홀수로
    while not _is_probable_prime(n):
        n += 2
    return n


def _gen_keys():
    if PATCHED:
        # 패치: 서로 독립적인 임의 대형 소수(구조 없음) → Fermat/대수적 인수분해 불가.
        p = _next_prime((_seeded_int("patch-p", 512) | (1 << 511)))
        q = _next_prime((_seeded_int("patch-q", 512) | (1 << 511)))
    else:
        # 취약: p = 2^512 + a, q = 2^512 + b (a,b 약 63비트) → 모듈러스에 대수적 구조.
        base = 1 << 512
        a = _seeded_int("a", 63) | 1
        b = _seeded_int("b", 63) | 1
        p = _next_prime(base + a)
        q = _next_prime(base + b)
        if p == q:
            q = _next_prime(q + 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(E, -1, phi)
    return n, d


_N, _D = _gen_keys()
_AES_KEY = hashlib.sha256(f"aeskey:{CHALLENGE_SECRET}".encode()).digest()  # 32B
_AES_IV = hashlib.sha256(f"aesiv:{CHALLENGE_SECRET}".encode()).digest()[:16]


def _pkcs7(data: bytes, block: int = 16) -> bytes:
    pad = block - (len(data) % block)
    return data + bytes([pad]) * pad


def _aes_cbc_encrypt(pt: bytes) -> bytes:
    enc = Cipher(algorithms.AES(_AES_KEY), modes.CBC(_AES_IV)).encryptor()
    return enc.update(_pkcs7(pt)) + enc.finalize()


def _rsa_wrap_key() -> int:
    """AES 키(32B)를 정수로 RSA 암호화(c = K^e mod N)."""
    k_int = int.from_bytes(_AES_KEY, "big")
    return pow(k_int, E, _N)


@app.get("/health")
def health():
    return {"status": "ok", "patched": PATCHED, "service": "lng-terminal-vault"}


@app.get("/api/version")
def version():
    return {"protocol": "ad-http-v1", "service": "lng-terminal-vault"}


@app.get("/api/vault/pubkey")
def pubkey():
    """LNG 문서 금고 공개키(N, e). 취약 키생성이면 N 에 대수적 구조가 남는다."""
    return {"N": format(_N, "x"), "e": E, "bits": _N.bit_length()}


@app.get("/api/vault/document")
def document():
    """RSA 로 감싼 AES 키 + AES-CBC 로 봉인된 LNG 계량 문서(flag)."""
    doc = (
        "LNG TERMINAL METERING REPORT / CLASSIFIED\n"
        "unit: Incheon LNG Terminal T-3\n"
        f"override_token: {static_flag()}\n"
    ).encode()
    return {
        "rsa_wrapped_key": format(_rsa_wrap_key(), "x"),
        "aes_iv": _AES_IV.hex(),
        "aes_ciphertext": _aes_cbc_encrypt(doc).hex(),
        "kdf": "raw-32B-int",
        "aes_mode": "CBC/PKCS7",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8135)
