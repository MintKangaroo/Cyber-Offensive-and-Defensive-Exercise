"""AI-000 배포 - 피싱 탐지기 predict API."""
import pickle
import hmac
import hashlib
import os
from pathlib import Path
from fastapi import FastAPI
from pydantic import BaseModel

APP_DIR = Path(__file__).parent
CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "ai000-dev-secret")
FEATURE_NAMES = ["length", "dot_count", "special_char_count", "has_at", "is_ip_like", "has_keyword"]

app = FastAPI(title="AI-000 Challenge Deploy (TRAINING ONLY)")

with open(APP_DIR / "detector.pkl", "rb") as f:
    model = pickle.load(f)


def dynamic_flag(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"AI-000:{team_id}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"flag{{feature_space_evasion_{sig}}}"


class FeatureVector(BaseModel):
    length: float
    dot_count: float
    special_char_count: float
    has_at: int
    is_ip_like: int
    has_keyword: int
    team_id: str = "default"


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/predict")
def predict(fv: FeatureVector):
    vector = [[getattr(fv, name) for name in FEATURE_NAMES]]
    score = float(model.predict_proba(vector)[0][1])
    result = {"malicious_score": score, "verdict": "malicious" if score >= 0.5 else "benign"}
    if score < 0.5:
        result["flag"] = dynamic_flag(fv.team_id)
    return result


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8102)
