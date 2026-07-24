"""
WEB-002 배포용 취약 서비스 (독립 실행형 — 전체 ground_station 트윈에 의존하지 않음)
================================================================================
11번 문서의 출제표준대로 각 챌린지는 독립 배포 가능해야 하므로, ground_station의
GS-002/JWT 로직을 최소 재현한 스탠드얼론 앱으로 만든다. 취약점 로직은 동일:
alg=none 수용 + 약한 대칭키.
"""
import os
import time
import hmac
import hashlib
from fastapi import FastAPI, HTTPException, Header
import jwt

app = FastAPI(title="WEB-002 Challenge Deploy (TRAINING ONLY)")

JWT_SECRET = "supersecret123"  # 의도된 취약 시크릿(문서화됨, 08번 안전장치 secret_scan 허용리스트 대상)
CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "web002-dev-secret")  # 동적 플래그 HMAC 키
PATCHED = os.environ.get("PATCH_WEB_002", "false").lower() == "true"


def dynamic_flag(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"WEB-002:{team_id}".encode(), hashlib.sha256).hexdigest()[:16]
    return f"flag{{jwt_forged_{sig}}}"


@app.get("/health")
def health():
    return {"status": "ok", "patched": PATCHED}


@app.post("/api/mission/approve")
def approve_mission(authorization: str = Header(default=""), x_team_id: str = Header(default="default")):
    token = authorization.replace("Bearer ", "")

    if PATCHED:
        secret = os.environ.get("GS_JWT_STRONG_SECRET", "")
        try:
            payload = jwt.decode(token, secret, algorithms=["HS256"])
        except Exception:
            raise HTTPException(401, "invalid token")
    else:
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") == "none":
                payload = jwt.decode(token, options={"verify_signature": False})
            else:
                payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except Exception:
            raise HTTPException(401, "invalid token")

    if payload.get("role") != "admin":
        raise HTTPException(403, "admin only")

    approval_flag = dynamic_flag(x_team_id)
    return {"status": "approved", "approval_code": approval_flag}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8100)
