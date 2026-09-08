"""CRY-001 배포용 서비스 — 전력망 원격검침 세션(AES-CBC 패딩 오라클).

세션 토큰을 AES-CBC 로 암호화한다. 검증 엔드포인트가 패딩 유효/무효를 응답으로 구분해줘서
(패딩 오라클) 제공된 관리자 세션 암호문을 키 없이 한 바이트씩 복호할 수 있고, 평문에 비상
검침 토큰(flag)이 들어 있다. PATCH_CRY_001=true 면 인증암호(AES-GCM)로 바꿔 오라클을 없앤다.
"""
import hashlib
import os

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = FastAPI(title="CRY-001 Grid Metering Session (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_CRY_001", "false").lower() == "true"
_KEY = hashlib.sha256(f"cbckey:{CHALLENGE_SECRET}".encode()).digest()[:16]
_IV = hashlib.sha256(f"cbciv:{CHALLENGE_SECRET}".encode()).digest()[:16]


def static_flag() -> str:
    sig = hashlib.sha256(f"CRY-001:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{cbc_padding_oracle_{sig}}}"


def _pkcs7(b: bytes, bs: int = 16) -> bytes:
    p = bs - (len(b) % bs)
    return b + bytes([p]) * p


def _unpad(b: bytes) -> bytes:
    if not b or len(b) % 16 != 0:
        raise ValueError("len")
    p = b[-1]
    if p < 1 or p > 16 or b[-p:] != bytes([p]) * p:
        raise ValueError("pad")
    return b[:-p]


_ADMIN_PT = f"role=admin;meter_master={static_flag()}".encode()


class Token(BaseModel):
    token: str = Field(min_length=2, max_length=4096)


@app.get("/health")
def health():
    return {"status": "ok", "patched": PATCHED, "service": "grid-metering-session"}


@app.get("/api/version")
def version():
    return {"protocol": "ad-http-v1", "service": "grid-metering-session"}


@app.get("/api/session/challenge")
def challenge():
    """관리자 세션 암호문(hex(iv||ct)) — 복호하면 평문에 flag."""
    if PATCHED:
        aes = AESGCM(_KEY)
        ct = aes.encrypt(_IV[:12], _ADMIN_PT, None)
        return {"token": (_IV[:12] + ct).hex(), "mode": "GCM"}
    c = Cipher(algorithms.AES(_KEY), modes.CBC(_IV)).encryptor()
    ct = c.update(_pkcs7(_ADMIN_PT)) + c.finalize()
    return {"token": (_IV + ct).hex(), "mode": "CBC"}


@app.post("/api/session/verify")
def verify(req: Token):
    """세션 검증 — 패딩 유효/무효를 응답으로 구분(취약: 패딩 오라클)."""
    raw = bytes.fromhex(req.token)
    if PATCHED:
        # 방어: 인증암호(GCM). 태그 불일치는 단일 오류(오라클 없음).
        try:
            AESGCM(_KEY).decrypt(raw[:12], raw[12:], None)
            return {"ok": True}
        except Exception:
            raise HTTPException(400, "invalid session")
    iv, ct = raw[:16], raw[16:]
    if not ct or len(ct) % 16 != 0:
        raise HTTPException(400, "length")
    d = Cipher(algorithms.AES(_KEY), modes.CBC(iv)).decryptor()
    pt = d.update(ct) + d.finalize()
    try:
        _unpad(pt)  # 취약: 패딩 검증 결과를 응답으로 노출
    except ValueError:
        raise HTTPException(400, "bad padding")
    return {"ok": True}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8133)
