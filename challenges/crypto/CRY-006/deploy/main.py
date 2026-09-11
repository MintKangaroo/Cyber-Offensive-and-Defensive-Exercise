"""CRY-006 배포용 서비스 — 관세청 전자통관 API(해시 길이확장 서명 위조).

요청 파라미터를 MAC = SHA256(SECRET ‖ message) 로 서명한다(secret-prefix 해시 = 잘못된 MAC).
SHA-256 은 Merkle–Damgård 라 알려진 MAC 을 내부 상태로 삼아 이어서 해시할 수 있어(length
extension), SECRET 없이도 message‖padding‖extension 의 유효 MAC 을 만들 수 있다. 공격자는
GET / 이 준 정상 서명으로 '&role=admin' 을 덧붙여 위조 → /api/clear 로 flag.

PATCH_CRY_006=true 면 HMAC-SHA256 으로 교체해 길이확장 위조를 차단한다.
"""
import hashlib
import hmac
import os

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="CRY-006 Customs e-Clearance API (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그/키 시드는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_CRY_006", "false").lower() == "true"

# MAC 키: 길이는 공격자에게 알리지 않는다(8..24바이트, secret 로 결정). 실제 서명키 아님.
_KLEN = 8 + (int.from_bytes(hashlib.sha256(("CRY-006:len:" + CHALLENGE_SECRET).encode()).digest(), "big") % 17)
KEY = hashlib.sha256(("CRY-006:key:" + CHALLENGE_SECRET).encode()).digest()[:_KLEN]

# 정상 서명되어 배포되는 요청(관리자 아님).
ORIGINAL_MESSAGE = b"action=declare&importer=guest&hs=8471.30"


def static_flag() -> str:
    sig = hashlib.sha256(f"CRY-006:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{length_extension_{sig}}}"


def mac(message: bytes) -> str:
    if PATCHED:
        return hmac.new(KEY, message, hashlib.sha256).hexdigest()
    return hashlib.sha256(KEY + message).hexdigest()  # secret-prefix MAC (취약)


class ClearReq(BaseModel):
    message: str  # hex
    mac: str      # hex


@app.get("/")
def index():
    return {
        "service": "customs e-clearance",
        "note": "요청은 MAC=SHA256(SECRET||message) 로 서명됩니다. (TRAINING ONLY)",
        "signed_request": {
            "message_hex": ORIGINAL_MESSAGE.hex(),
            "message": ORIGINAL_MESSAGE.decode(),
            "mac": mac(ORIGINAL_MESSAGE),
        },
        "verify_endpoint": "POST /api/clear {message: hex, mac: hex}",
        "grant_rule": "MAC 유효 + message 에 role=admin 포함 시 flag",
        "patched": PATCHED,
    }


@app.post("/api/clear")
def clear(req: ClearReq):
    try:
        message = bytes.fromhex(req.message)
    except ValueError:
        return {"ok": False, "detail": "message must be hex"}
    if req.mac.strip().lower() != mac(message):
        return {"ok": False, "detail": "invalid MAC"}
    if b"role=admin" not in message:
        return {"ok": False, "detail": "authenticated, but not an admin request"}
    return {"ok": True, "flag": static_flag()}
