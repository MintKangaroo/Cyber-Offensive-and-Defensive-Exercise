"""CRY-011 배포용 서비스 — 펌웨어 매니페스트 ECDSA 서명(secp256k1) 논스 재사용.

관제 시스템이 펌웨어 업데이트 매니페스트 두 건을 ECDSA(secp256k1)로 서명해 공개한다. 그러나
서명 논스 k 를 두 메시지에 그대로 재사용한다(고정 시드 버그). 논스가 같으면 두 서명의 r 이
동일하고, s1-s2 = k^-1 (z1-z2) 에서 k 를, 이어서 d = (s1·k - z1)·r^-1 에서 개인키 d 를 복구할 수
있다. 복구한 개인키를 제출하면 flag.

PATCH_CRY_011=true 면 메시지별로 서로 다른 결정적(RFC6979 유사) 논스를 써서 r 이 달라지고
재사용 공격이 무력화된다.
"""
import hashlib
import hmac
import os

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="CRY-011 Firmware Manifest ECDSA Signer (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 개인키/논스 시드는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_CRY_011", "false").lower() == "true"

# secp256k1 도메인 파라미터
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)


def _inv(a: int, m: int) -> int:
    return pow(a % m, -1, m)


def _add(pt1, pt2):
    if pt1 is None:
        return pt2
    if pt2 is None:
        return pt1
    x1, y1 = pt1
    x2, y2 = pt2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if pt1 == pt2:
        lam = (3 * x1 * x1) * _inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * _inv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def _mul(k: int, pt):
    res = None
    addend = pt
    k %= N
    while k:
        if k & 1:
            res = _add(res, addend)
        addend = _add(addend, addend)
        k >>= 1
    return res


def static_flag() -> str:
    sig = hashlib.sha256(f"CRY-011:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{ecdsa_nonce_reuse_{sig}}}"


def _seed_scalar(tag: str) -> int:
    h = hashlib.sha256(f"CRY-011:{tag}:{CHALLENGE_SECRET}".encode()).digest()
    return (int.from_bytes(h, "big") % (N - 1)) + 1


PRIV = _seed_scalar("private-key")
PUB = _mul(PRIV, G)

MESSAGES = [
    "firmware-manifest v41 sha256=deploy-substation-A ttl=3600",
    "firmware-manifest v42 sha256=deploy-substation-B ttl=3600",
]


def _z(msg: str) -> int:
    return int.from_bytes(hashlib.sha256(msg.encode()).digest(), "big") % N


def _nonce(msg: str, idx: int) -> int:
    if PATCHED:
        # RFC6979 유사: 메시지별로 서로 다른 결정적 논스 → r 이 달라져 재사용 공격 불가.
        mac = hmac.new(
            PRIV.to_bytes(32, "big"),
            f"{msg}:{idx}".encode(),
            hashlib.sha256,
        ).digest()
        return (int.from_bytes(mac, "big") % (N - 1)) + 1
    # 취약: 논스를 두 메시지에 그대로 재사용(메시지·인덱스와 무관하게 고정).
    return _seed_scalar("reused-nonce")


def _sign(msg: str, idx: int):
    z = _z(msg)
    k = _nonce(msg, idx)
    r = _mul(k, G)[0] % N
    s = (_inv(k, N) * (z + r * PRIV)) % N
    return z, r, s


SIGNATURES = []
for _i, _m in enumerate(MESSAGES):
    _z_val, _r, _s = _sign(_m, _i)
    SIGNATURES.append({"msg": _m, "z": hex(_z_val), "r": hex(_r), "s": hex(_s)})


class RecoverReq(BaseModel):
    d: str  # hex 개인키


@app.get("/")
def index():
    return {
        "service": "firmware manifest ECDSA signer",
        "curve": "secp256k1",
        "note": "펌웨어 매니페스트 2건을 ECDSA 로 서명해 공개합니다. (TRAINING ONLY)",
        "endpoints": ["GET /api/signed", "POST /api/recover {d: hex}"],
        "patched": PATCHED,
    }


@app.get("/api/signed")
def signed():
    return {
        "curve": "secp256k1",
        "n": hex(N),
        "pubkey": {"x": hex(PUB[0]), "y": hex(PUB[1])},
        "signatures": SIGNATURES,
    }


@app.post("/api/recover")
def recover(req: RecoverReq):
    try:
        submitted = int(req.d, 16) % N
    except ValueError:
        return {"ok": False, "detail": "d must be hex integer"}
    if submitted == PRIV:
        return {"ok": True, "flag": static_flag()}
    return {"ok": False, "detail": "invalid private key"}
