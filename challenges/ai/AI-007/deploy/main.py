"""
AI-007 배포 - 예산 제약 적대적 회피(PGD) 챌린지 서버.

/model    : 화이트박스 가중치(W1,b1,W2,b2) 공개 → Red가 그래디언트 계산 가능.
/source   : 소스 샘플 x0(진짜 malware), L∞ 예산 eps, 특징명, 박스 제약 안내.
/classify : 제출 벡터 x를 검사 —
            (1) x가 [0,1]^8 박스 안인가, (2) ||x - x0||_inf <= eps 예산 안인가,
            (3) 모델이 benign으로 분류하는가. 셋 다 만족(=예산 안의 유효한 회피)이면 플래그 발급.
            예산을 벗어난 회피(AI-000식 특징 몰아넣기)는 명시적으로 거부한다.
"""
import hmac
import hashlib
import os
from pathlib import Path

import numpy as np
from fastapi import FastAPI
from pydantic import BaseModel

APP_DIR = Path(__file__).parent
CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "ai007-dev-secret")
TOL = 1e-6  # 부동소수 비교 허용 오차

_m = np.load(APP_DIR / "model.npz", allow_pickle=True)
W1, b1, W2, b2 = _m["W1"], _m["b1"], _m["W2"], _m["b2"]
X0 = _m["x0"].astype(float)
EPS = float(_m["eps"])
FEATURE_NAMES = [str(s) for s in _m["feature_names"]]
D = len(FEATURE_NAMES)

app = FastAPI(title="AI-007 Challenge Deploy (adversarial-evasion, TRAINING ONLY)")


def _softmax(z):
    z = z - z.max()
    e = np.exp(z)
    return e / e.sum()


def malware_prob(x: np.ndarray) -> float:
    a1 = np.maximum(0, x @ W1 + b1)
    return float(_softmax(a1 @ W2 + b2)[1])


def dynamic_flag(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"AI-007:{team_id}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"flag{{pgd_evasion_{sig}}}"


class ClassifyRequest(BaseModel):
    x: list[float]
    team_id: str = "default"


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/model")
def get_model():
    """화이트박스 가중치 공개(Red가 그래디언트 기반 공격을 설계할 수 있도록)."""
    return {
        "arch": "mlp: h=relu(W1 x + b1); logits=W2 h + b2; classes=[benign, malware]",
        "W1": W1.tolist(), "b1": b1.tolist(),
        "W2": W2.tolist(), "b2": b2.tolist(),
        "feature_names": FEATURE_NAMES,
    }


@app.get("/source")
def get_source():
    return {
        "x0": X0.tolist(),
        "true_label": "malware",
        "malware_prob": malware_prob(X0),
        "epsilon_linf": EPS,
        "box": [0.0, 1.0],
        "feature_names": FEATURE_NAMES,
        "objective": "예산 ||x - x0||_inf <= epsilon, x in [0,1]^8 안에서 benign 오분류를 유도하라.",
    }


@app.post("/classify")
def classify(req: ClassifyRequest):
    if len(req.x) != D:
        return {"error": f"x must have length {D}"}
    x = np.array(req.x, dtype=float)

    if np.any(x < -TOL) or np.any(x > 1 + TOL):
        return {"rejected": "box", "detail": "x must lie in [0,1]^8"}

    linf = float(np.abs(x - X0).max())
    if linf > EPS + TOL:
        return {"rejected": "budget",
                "detail": f"L-inf perturbation {linf:.4f} exceeds epsilon {EPS} (예산 초과 회피는 무효)",
                "linf": linf, "epsilon": EPS}

    p = malware_prob(x)
    result = {"malware_prob": p, "verdict": "malware" if p >= 0.5 else "benign", "linf": linf}
    if p < 0.5:
        result["flag"] = dynamic_flag(req.team_id)
    return result


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8107)
