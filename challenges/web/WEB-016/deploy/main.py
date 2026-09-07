"""WEB-016 배포용 서비스 — 재난 긴급 에너지 바우처 발급소(레이스 컨디션 / TOCTOU).

재난안전 긴급 에너지 바우처는 계정당 1장만 상환(redeem)할 수 있다. 그러나 상환 처리가
'잔량 확인 → (지연) → 차감'으로 원자적이지 않아(TOCTOU), 동시에 여러 요청을 보내면 같은
잔량을 여러 요청이 통과해 1장 한도를 넘겨 상환된다(이중 청구). 한도를 초과해 상환되면
비상 정산 토큰(flag)이 발급된다.

PATCH_WEB_016=true 면 확인-차감을 락으로 원자화해 레이스를 차단한다.
"""
import hashlib
import os
import threading
import time

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="WEB-016 Emergency Energy Voucher (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_WEB_016", "false").lower() == "true"
RACE_WINDOW = float(os.environ.get("RACE_WINDOW_SEC", "0.08"))

# account -> {"balance": int, "redeemed": int}
_ACCTS: dict[str, dict] = {}
_LOCK = threading.Lock()


def static_flag() -> str:
    sig = hashlib.sha256(f"WEB-016:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{voucher_race_{sig}}}"


class Acct(BaseModel):
    account: str


@app.get("/health")
def health():
    return {"status": "ok", "patched": PATCHED, "service": "emergency-voucher"}


@app.get("/api/version")
def version():
    return {"protocol": "ad-http-v1", "service": "emergency-voucher"}


@app.post("/api/voucher/issue")
def issue():
    import secrets
    acc = secrets.token_urlsafe(9)
    _ACCTS[acc] = {"balance": 1, "redeemed": 0}
    return {"account": acc, "balance": 1, "quota": 1}


def _grant(st: dict) -> dict:
    st["balance"] -= 1
    st["redeemed"] += 1
    if st["redeemed"] > 1:
        # 한도(1) 초과 상환 성공 = 레이스 성립
        return {"redeemed": st["redeemed"], "over_quota": True, "flag": static_flag()}
    return {"redeemed": st["redeemed"], "over_quota": False}


@app.post("/api/voucher/redeem")
def redeem(req: Acct):
    st = _ACCTS.get(req.account)
    if st is None:
        raise HTTPException(404, "계정 없음 — /api/voucher/issue 먼저")
    if PATCHED:
        # 방어: 확인-차감을 원자화(락)
        with _LOCK:
            if st["balance"] <= 0:
                raise HTTPException(409, "잔량 없음")
            return _grant(st)
    # 취약: 확인 → (지연) → 차감 이 비원자적(TOCTOU)
    if st["balance"] <= 0:
        raise HTTPException(409, "잔량 없음")
    time.sleep(RACE_WINDOW)  # 확인과 차감 사이 윈도우
    return _grant(st)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8116)
