"""CRY-000 배포용 서비스 — 국가 재난망 토큰 암호화 오라클(AES-ECB byte-at-a-time).

재난망 토큰 발급기가 사용자 입력 뒤에 비밀(비상 마스터 토큰=flag)을 붙여 AES-ECB 로 암호화해
돌려준다. ECB 는 같은 평문 블록이 같은 암호블록이 되므로, 입력 길이를 조절해 블록 경계를 맞추면
비밀을 한 바이트씩 복구할 수 있다(byte-at-a-time). PATCH_CRY_000=true 면 ECB 대신 임의 IV 의
CBC 를 써서 이 공격을 무력화한다.
"""
import hashlib
import os

from fastapi import FastAPI
from pydantic import BaseModel, Field
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = FastAPI(title="CRY-000 Disaster Token Oracle (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_CRY_000", "false").lower() == "true"
_KEY = hashlib.sha256(f"key:{CHALLENGE_SECRET}".encode()).digest()[:16]


def static_flag() -> str:
    sig = hashlib.sha256(f"CRY-000:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{ecb_byte_oracle_{sig}}}"


def _pkcs7(b: bytes, bs: int = 16) -> bytes:
    p = bs - (len(b) % bs)
    return b + bytes([p]) * p


class EncReq(BaseModel):
    data: str = Field(default="", max_length=512)


@app.get("/health")
def health():
    return {"status": "ok", "patched": PATCHED, "service": "disaster-token-oracle"}


@app.get("/api/version")
def version():
    return {"protocol": "ad-http-v1", "service": "disaster-token-oracle"}


@app.post("/api/token/encrypt")
def encrypt(req: EncReq):
    """user_input || SECRET 을 암호화해 hex 로 반환."""
    pt = _pkcs7(req.data.encode() + static_flag().encode())
    if PATCHED:
        import os as _os
        iv = _os.urandom(16)
        c = Cipher(algorithms.AES(_KEY), modes.CBC(iv)).encryptor()
        ct = c.update(pt) + c.finalize()
        return {"ciphertext": (iv + ct).hex(), "mode": "CBC"}
    c = Cipher(algorithms.AES(_KEY), modes.ECB()).encryptor()  # 취약: ECB
    ct = c.update(pt) + c.finalize()
    return {"ciphertext": ct.hex(), "mode": "ECB"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8130)
