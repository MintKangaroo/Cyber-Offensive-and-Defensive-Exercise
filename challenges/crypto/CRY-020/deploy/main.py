"""CRY-020 배포용 서비스 — 재난경보 위성 명령 업링크, RSA e=3 관련 메시지(Franklin-Reiter).

동일한 명령 페이로드 M 을 두 개의 연속 프레임으로 전송하는데, 두 프레임은 저비트 프레임 카운터만
다르므로 두 평문 사이에 알려진 선형 관계 m2 = m1 + delta 가 성립한다. 두 프레임 모두 작은 공개지수
e=3 으로 같은 모듈러스 N 에 암호화된다. g1(x)=x^3-c1, g2(x)=(x+delta)^3-c2 는 x=m1 을 공통근으로
가지므로 Z_N[x] 에서 다항식 GCD 를 구하면 선형 인수가 남아 개인키 없이 m1 을 복구할 수 있다
(Franklin-Reiter 관련 메시지 공격).

PATCH_CRY_020=true 면 프레임마다 무작위 패딩을 적용해 두 평문 사이 알려진 대수 관계를 없앤다.
"""
import hashlib
import os
import random

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="CRY-020 Disaster-Alert Satellite Uplink (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — RSA 키/토큰 시드는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_CRY_020", "false").lower() == "true"
E = 3


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


def _prime_e3(rnd, bits):
    """e=3 가 (p-1) 과 서로소가 되도록 p % 3 != 1 인 소수 생성."""
    while True:
        p = rnd.getrandbits(bits) | (1 << (bits - 1)) | 1
        if p % 3 != 1 and _is_prime(p):
            return p


def _rng(tag):
    return random.Random(hashlib.sha256(f"CRY-020:{tag}:{CHALLENGE_SECRET}".encode()).digest())


_p = _prime_e3(_rng("p"), 512)
_q = _prime_e3(_rng("q"), 512)
N = _p * _q

# 명령 토큰(제출 대상). 평문 프레임은 UPLINK:<token>:EOF 형태로 감싼다.
TOKEN = "SATCMD-" + hashlib.sha256(f"CRY-020:token:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
_PT = b"UPLINK:" + TOKEN.encode() + b":EOF"
_M1 = int.from_bytes(_PT, "big")

# 공개된 프레임 카운터 증가분(두 프레임의 알려진 선형 차이).
DELTA = int(hashlib.sha256(f"CRY-020:delta:{CHALLENGE_SECRET}".encode()).hexdigest()[:8], 16) | 1

if PATCHED:
    # 패치: 프레임마다 독립 무작위 패딩 → 두 평문 사이 알려진 대수 관계 소멸.
    _pad_rng = _rng("oaep")
    _pad1 = _pad_rng.getrandbits(600) << 320
    _pad2 = _pad_rng.getrandbits(600) << 320
    _m1_enc = (_pad1 | _M1) % N
    _m2_enc = (_pad2 | _M1) % N
    C1 = pow(_m1_enc, E, N)
    C2 = pow(_m2_enc, E, N)
else:
    # 취약: 동일 평문의 두 관련 메시지(선형 관계 m2 = m1 + DELTA).
    C1 = pow(_M1, E, N)
    C2 = pow((_M1 + DELTA), E, N)


def static_flag():
    sig = hashlib.sha256(f"CRY-020:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{franklin_reiter_related_msg_{sig}}}"


class RecoverReq(BaseModel):
    token: str


@app.get("/")
def index():
    return {
        "service": "disaster-alert satellite command uplink",
        "note": "동일 명령을 두 프레임으로 전송(프레임 카운터 delta 만 차이). e=3. 명령 토큰을 복구해 제출. (TRAINING ONLY)",
        "endpoints": ["GET /api/frames", "POST /api/recover {token}"],
        "patched": PATCHED,
    }


@app.get("/api/frames")
def frames():
    return {
        "e": E,
        "N": hex(N),
        "c1": hex(C1),
        "c2": hex(C2),
        "delta": hex(DELTA),
        "note": "frame2 평문 = frame1 평문 + delta (프레임 카운터 증가분). 두 프레임 모두 e=3 으로 암호화.",
    }


@app.post("/api/recover")
def recover(req: RecoverReq):
    if req.token.strip() == TOKEN:
        return {"ok": True, "flag": static_flag()}
    return {"ok": False, "detail": "incorrect token"}
