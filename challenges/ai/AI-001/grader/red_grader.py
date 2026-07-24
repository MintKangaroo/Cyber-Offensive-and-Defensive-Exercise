"""AI-001 Red Grader - victim과 surrogate의 held-out 일치율 >= 90%면 통과."""
import pickle
import sys
from pathlib import Path
from dataclasses import dataclass
import numpy as np


@dataclass
class GradeResult:
    passed: bool
    points: int
    detail: str = ""


AGREEMENT_THRESHOLD = 0.90


def grade_red(submission: dict, context: dict) -> GradeResult:
    challenge_dir = Path(context.get("challenge_dir", Path(__file__).parent.parent))
    victim_path = challenge_dir / "deploy" / "victim.pkl"
    surrogate_path = Path(submission.get("surrogate_path", challenge_dir / "solution" / "surrogate.pkl"))

    if not victim_path.exists() or not surrogate_path.exists():
        return GradeResult(False, 0, "victim.pkl 또는 surrogate.pkl 없음")

    with open(victim_path, "rb") as f:
        victim = pickle.load(f)
    with open(surrogate_path, "rb") as f:
        surrogate = pickle.load(f)

    # grader 전용 held-out 테스트셋(추출에 쓰인 쿼리와 겹치지 않는 새 시드)
    rng = np.random.RandomState(999)
    X_test = rng.uniform(low=[5, 0, 0, 0, 0, 0], high=[100, 10, 20, 1, 1, 1], size=(200, 6))

    victim_labels = (victim.predict_proba(X_test)[:, 1] >= 0.5).astype(int)
    surrogate_labels = (surrogate.predict_proba(X_test)[:, 1] >= 0.5).astype(int)

    agreement = float(np.mean(victim_labels == surrogate_labels))
    passed = agreement >= AGREEMENT_THRESHOLD
    points = 150 if passed else int(150 * max(0, agreement - 0.5) / (AGREEMENT_THRESHOLD - 0.5))

    return GradeResult(passed, points, f"held-out agreement={agreement:.3f} (threshold={AGREEMENT_THRESHOLD})")
