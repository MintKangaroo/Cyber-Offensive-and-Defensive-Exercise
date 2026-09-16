"""CRY-015 배포용 서비스 — 위성 원격측정 서명기 ECDSA 편향 논스(HNP 격자 공격).

위성 원격측정 게이트웨이가 secp256k1 ECDSA 로 여러 메시지를 서명해 공개한다. 그러나 서명 논스 k
를 128비트로만 생성한다(상위 비트가 0 인 편향). 편향된 논스는 Hidden Number Problem 으로 환원되어
여러 서명을 모으면 격자 축약(LLL)으로 개인키 d 를 복구할 수 있다. 복구한 d 를 제출하면 flag.

PATCH_CRY_015=true 면 RFC6979 결정적 논스(전체 구간)를 써서 편향이 사라져 격자 공격이 불가능해진다.
"""
import hashlib
import hmac
import os

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="CRY-015 Satellite Telemetry ECDSA Signer (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 개인키/논스 시드는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_CRY_015", "false").lower() == "true"

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
NONCE_BITS = 128
NUM_SIGS = 12


def _inv(a, m):
    return pow(a % m, -1, m)


def _add(Pt, Qt):
    if Pt is None:
        return Qt
    if Qt is None:
        return Pt
    if Pt[0] == Qt[0] and (Pt[1] + Qt[1]) % P == 0:
        return None
    if Pt == Qt:
        l = (3 * Pt[0] * Pt[0]) * _inv(2 * Pt[1], P) % P
    else:
        l = (Qt[1] - Pt[1]) * _inv(Qt[0] - Pt[0], P) % P
    x = (l * l - Pt[0] - Qt[0]) % P
    y = (l * (Pt[0] - x) - Pt[1]) % P
    return (x, y)


def _mul(k, Pt=(GX, GY)):
    R = None
    A = Pt
    k %= N
    while k:
        if k & 1:
            R = _add(R, A)
        A = _add(A, A)
        k >>= 1
    return R


D = (int.from_bytes(hashlib.sha256(f"CRY-015:d:{CHALLENGE_SECRET}".encode()).digest(), "big") % (N - 1)) + 1
PUB = _mul(D)


def static_flag():
    sig = hashlib.sha256(f"CRY-015:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{ecdsa_biased_nonce_lattice_{sig}}}"


def _rfc6979_nonce(z, msgtag):
    # 결정적 논스(전체 구간) — 패치 모드.
    key = D.to_bytes(32, "big")
    mac = hmac.new(key, f"{z}:{msgtag}".encode(), hashlib.sha256).digest()
    return (int.from_bytes(mac, "big") % (N - 1)) + 1


def _biased_nonce(idx):
    # 취약: 128비트 편향 논스(상위 비트 0).
    h = hashlib.sha256(f"CRY-015:k:{idx}:{CHALLENGE_SECRET}".encode()).digest()
    return (int.from_bytes(h, "big") % ((1 << NONCE_BITS) - 1)) + 1


def _z(msg):
    return int.from_bytes(hashlib.sha256(msg.encode()).digest(), "big") % N


SIGNATURES = []
for _i in range(NUM_SIGS):
    _msg = f"telemetry-frame-{_i:03d} attitude=nominal"
    _zz = _z(_msg)
    _k = _rfc6979_nonce(_zz, _i) if PATCHED else _biased_nonce(_i)
    _r = _mul(_k)[0] % N
    _s = (_inv(_k, N) * (_zz + _r * D)) % N
    SIGNATURES.append({"msg": _msg, "z": hex(_zz), "r": hex(_r), "s": hex(_s)})


class RecoverReq(BaseModel):
    d: str  # hex or decimal


@app.get("/")
def index():
    return {
        "service": "satellite telemetry ECDSA signer",
        "curve": "secp256k1",
        "note": "원격측정 프레임을 ECDSA 로 서명해 공개. (TRAINING ONLY)",
        "endpoints": ["GET /api/params", "GET /api/signatures", "POST /api/recover {d}"],
        "patched": PATCHED,
    }


@app.get("/api/params")
def params():
    return {
        "curve": "secp256k1",
        "n": hex(N),
        "pubkey": {"x": hex(PUB[0]), "y": hex(PUB[1])},
        "nonce_bits": NONCE_BITS,
        "num_signatures": NUM_SIGS,
    }


@app.get("/api/signatures")
def signatures():
    return {"signatures": SIGNATURES}


@app.post("/api/recover")
def recover(req: RecoverReq):
    raw = req.d.strip()
    try:
        submitted = (int(raw, 16) if raw.lower().startswith("0x") else int(raw)) % N
    except ValueError:
        return {"ok": False, "detail": "d must be integer"}
    if submitted == D:
        return {"ok": True, "flag": static_flag()}
    return {"ok": False, "detail": "incorrect private key"}
