"""CRY-013 배포용 서비스 — 재난경보 방송 명령 인증(AES-GCM) 논스 재사용(forbidden attack).

방송 관제가 두 상태 메시지를 AES-GCM 으로 인증·암호화해 공개한다. 그러나 같은 nonce 를 두
메시지에 재사용한다(고정 nonce 버그). 논스가 같으면 두 태그의 차이가 GHASH 부분키 H 에 대한
GF(2^128) 다항식이 되어 H 를 복구할 수 있고(Joux 의 forbidden attack), 이어서 E_K(J0) 와
keystream 을 복구해 임의 명령의 유효한 태그를 위조할 수 있다. 위조한 관리자 명령을 제출하면 flag.

PATCH_CRY_013=true 면 메시지마다 서로 다른 무작위 nonce 를 써서 H 소거가 불가능해진다.
"""
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="CRY-013 Disaster Broadcast Command Auth (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — AES 키/논스 시드는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_CRY_013", "false").lower() == "true"

KEY = hashlib.sha256(f"CRY-013:key:{CHALLENGE_SECRET}".encode()).digest()[:16]
AAD = b"broadcast-hdr01"
# 취약: 두 메시지에 동일 nonce 재사용. 패치: 메시지마다 다른 무작위 nonce.
NONCE1 = hashlib.sha256(f"CRY-013:nonce:{CHALLENGE_SECRET}".encode()).digest()[:12]
NONCE2 = NONCE1 if not PATCHED else hashlib.sha256(
    f"CRY-013:nonce2:{CHALLENGE_SECRET}".encode()
).digest()[:12]

PT1 = b"STATUS all-clear zoneA".ljust(32, b" ")  # 공개된 알려진 평문
PT2 = b"STATUS gateB flow-nominal-42 ok!".ljust(32, b" ")

_g = AESGCM(KEY)
_c1 = _g.encrypt(NONCE1, PT1, AAD)
_c2 = _g.encrypt(NONCE2, PT2, AAD)
CT1, TAG1 = _c1[:-16], _c1[-16:]
CT2, TAG2 = _c2[:-16], _c2[-16:]


def static_flag() -> str:
    sig = hashlib.sha256(f"CRY-013:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{gcm_forbidden_nonce_reuse_{sig}}}"


class CommandReq(BaseModel):
    nonce: str  # hex
    aad: str    # hex
    ct: str     # hex
    tag: str    # hex


@app.get("/")
def index():
    return {
        "service": "disaster broadcast command auth",
        "cipher": "AES-128-GCM",
        "note": "두 상태 메시지를 GCM 으로 인증·공개. 관리자 명령은 유효한 태그가 있어야 실행. (TRAINING ONLY)",
        "endpoints": ["GET /api/messages", "POST /api/command {nonce,aad,ct,tag}"],
        "patched": PATCHED,
    }


@app.get("/api/messages")
def messages():
    return {
        "aad": AAD.hex(),
        "known_plaintext": PT1.decode(),
        "messages": [
            {"nonce": NONCE1.hex(), "ct": CT1.hex(), "tag": TAG1.hex()},
            {"nonce": NONCE2.hex(), "ct": CT2.hex(), "tag": TAG2.hex()},
        ],
    }


@app.post("/api/command")
def command(req: CommandReq):
    try:
        nonce = bytes.fromhex(req.nonce)
        aad = bytes.fromhex(req.aad)
        ct = bytes.fromhex(req.ct)
        tag = bytes.fromhex(req.tag)
    except ValueError:
        return {"ok": False, "detail": "fields must be hex"}
    try:
        pt = AESGCM(KEY).decrypt(nonce, ct + tag, aad)
    except Exception:
        return {"ok": False, "detail": "authentication failed (invalid tag)"}
    if pt.startswith(b"CMD unlock_all_valves=1 admin=1"):
        return {"ok": True, "flag": static_flag(), "executed": pt.decode(errors="replace")}
    return {"ok": True, "executed": pt.decode(errors="replace"), "note": "명령 인증됨(관리자 명령 아님)"}
