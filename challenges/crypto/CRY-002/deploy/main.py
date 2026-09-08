"""CRY-002 배포용 서비스 — 재난 통신 암호화(AES-CTR 논스 재사용 / keystream reuse).

비밀 메시지(flag)와 사용자 메시지를 '같은 키+논스'의 AES-CTR 로 암호화한다. CTR 은 키스트림
XOR 이므로 논스가 같으면 키스트림이 동일 → 사용자가 아는 평문을 암호화해 키스트림을 복원하고
flag 암호문에 XOR 해 flag 를 복호할 수 있다(many-time pad). PATCH_CRY_002=true 면 매 암호화마다
임의 논스를 써서(앞에 붙여) 재사용을 없앤다.
"""
import hashlib
import os

from fastapi import FastAPI
from pydantic import BaseModel, Field
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = FastAPI(title="CRY-002 Disaster Comms Crypto (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_CRY_002", "false").lower() == "true"
_KEY = hashlib.sha256(f"ctrkey:{CHALLENGE_SECRET}".encode()).digest()[:16]
_FIXED_NONCE = hashlib.sha256(f"ctrnonce:{CHALLENGE_SECRET}".encode()).digest()[:16]


def static_flag() -> str:
    sig = hashlib.sha256(f"CRY-002:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{ctr_nonce_reuse_{sig}}}"


def _ctr(nonce: bytes, data: bytes) -> bytes:
    c = Cipher(algorithms.AES(_KEY), modes.CTR(nonce)).encryptor()
    return c.update(data) + c.finalize()


class Msg(BaseModel):
    data: str = Field(min_length=1, max_length=512)


@app.get("/health")
def health():
    return {"status": "ok", "patched": PATCHED, "service": "disaster-comms-crypto"}


@app.get("/api/version")
def version():
    return {"protocol": "ad-http-v1", "service": "disaster-comms-crypto"}


@app.get("/api/comms/secret")
def secret():
    """비상 지령(flag)의 암호문. 취약: 고정 논스. 패치: 임의 논스 prepend."""
    pt = f"PRIORITY DISPATCH: {static_flag()}".encode()
    if PATCHED:
        n = os.urandom(16)
        return {"ciphertext": (n + _ctr(n, pt)).hex(), "mode": "CTR", "nonce": "prepended"}
    return {"ciphertext": _ctr(_FIXED_NONCE, pt).hex(), "mode": "CTR", "nonce": "fixed"}


@app.post("/api/comms/encrypt")
def encrypt(req: Msg):
    """사용자 메시지 암호화. 취약: secret 과 동일 고정 논스 → 키스트림 재사용."""
    pt = req.data.encode()
    if PATCHED:
        n = os.urandom(16)
        return {"ciphertext": (n + _ctr(n, pt)).hex(), "nonce": "prepended"}
    return {"ciphertext": _ctr(_FIXED_NONCE, pt).hex(), "nonce": "fixed"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8134)
