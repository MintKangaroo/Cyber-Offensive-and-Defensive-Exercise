"""WEB-000 배포용 취약 서비스 - 디버그 엔드포인트 노출."""
import os
import hmac
import hashlib
from fastapi import FastAPI, HTTPException, Header

app = FastAPI(title="WEB-000 Challenge Deploy (TRAINING ONLY)")

JWT_SECRET = "supersecret123"  # 의도된 취약 시크릿(더미)
CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "web000-dev-secret")
PATCHED = os.environ.get("PATCH_WEB_000", "false").lower() == "true"


def dynamic_flag(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"WEB-000:{team_id}".encode(), hashlib.sha256).hexdigest()[:16]
    return f"flag{{debug_exposed_{sig}}}"


@app.get("/health")
def health():
    return {"status": "ok", "patched": PATCHED}


@app.get("/api/debug/config")
def debug_config(x_team_id: str = Header(default="default")):
    if PATCHED:
        raise HTTPException(404, "not found")
    return {
        "patched": False,
        "jwt_secret": JWT_SECRET,
        "flag": dynamic_flag(x_team_id),
        "env": {"DEBUG": "true", "DB_PATH": "/app/ground_station.db"},
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8101)
