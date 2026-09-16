"""CRY-012 배포용 서비스 — 재난경보 방송 인증키 서버, smooth 소수 DLP(Pohlig-Hellman).

인증키 서버가 Diffie-Hellman 스타일 공개값 (p, g, h=g^x mod p) 을 게시한다. 그러나 소수 p 를
잘못 골라 p-1 이 작은 소인수들의 곱(smooth)이다. 이 경우 Pohlig-Hellman 으로 개인지수 x 를
복구할 수 있다. 복구한 x 를 제출하면 flag.

PATCH_CRY_012=true 면 safe prime(p=2q+1, q 대형 소수)으로 도메인을 재생성해 p-1 이 non-smooth 가
되어 이산로그 복구가 불가능해진다.
"""
import hashlib
import os

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="CRY-012 Disaster Alert DH Key Server (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 개인지수 시드는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_CRY_012", "false").lower() == "true"

# 취약 도메인: p-1 = 2 * (8개 소수, 각 < 2^30) → smooth. g=2 는 p-1 전체 위수의 생성원.
VULN_P = 0x246962b3e0bba09c0803073e3ac24a06ebffb9ea56a2e85e551d060c2cb
# 안전(패치) 도메인: safe prime p = 2q + 1 (q 대형 소수) → p-1 non-smooth.
SAFE_P = 0x2302748e8037dde37fc1c8217bb8d8972af1a170ab26ea8e66a75127177

G = 2
P = SAFE_P if PATCHED else VULN_P


def static_flag() -> str:
    sig = hashlib.sha256(f"CRY-012:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{pohlig_hellman_dlog_{sig}}}"


def _secret_exponent() -> int:
    h = hashlib.sha256(f"CRY-012:private-exponent:{CHALLENGE_SECRET}".encode()).digest()
    return (int.from_bytes(h, "big") % (P - 2)) + 1


X = _secret_exponent()
H = pow(G, X, P)


class RecoverReq(BaseModel):
    x: str  # 10진수 또는 0x hex 개인지수


@app.get("/")
def index():
    return {
        "service": "disaster alert DH key server",
        "note": "재난경보 방송망 인증키 공개값 (p, g, h=g^x mod p). (TRAINING ONLY)",
        "endpoints": ["GET /api/params", "POST /api/recover {x}"],
        "patched": PATCHED,
    }


@app.get("/api/params")
def params():
    return {"p": hex(P), "g": G, "h": hex(H)}


@app.post("/api/recover")
def recover(req: RecoverReq):
    raw = req.x.strip()
    try:
        submitted = int(raw, 16) if raw.lower().startswith("0x") else int(raw)
    except ValueError:
        return {"ok": False, "detail": "x must be an integer (decimal or 0x hex)"}
    # 이산로그 해는 위수 mod 로 유일 — pow 비교로 정답 확인(부분군 위수 배수도 허용).
    if pow(G, submitted, P) == H:
        return {"ok": True, "flag": static_flag()}
    return {"ok": False, "detail": "incorrect exponent"}
