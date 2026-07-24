"""AI-001 배포 - 쿼리 접근만 허용되는 'victim' 피싱 탐지기 학습(AI-000과 동일 구조, 독립 배포)."""
import pickle
import numpy as np
from sklearn.linear_model import LogisticRegression

FEATURE_NAMES = ["length", "dot_count", "special_char_count", "has_at", "is_ip_like", "has_keyword"]


def make_synthetic_dataset(n_per_class: int = 200, seed: int = 0):
    rng = np.random.RandomState(seed)
    X, y = [], []
    for _ in range(n_per_class):
        X.append([rng.uniform(10, 30), rng.uniform(1, 3), rng.uniform(0, 3), 0, 0, rng.choice([0, 0, 0, 1])])
        y.append(0)
    for _ in range(n_per_class):
        X.append([rng.uniform(40, 90), rng.uniform(4, 8), rng.uniform(5, 15),
                  rng.choice([0, 1]), rng.choice([0, 1]), 1])
        y.append(1)
    return np.array(X), np.array(y)


def train_and_save(model_path: str = "victim.pkl"):
    X, y = make_synthetic_dataset(seed=1)  # AI-000과 다른 seed(별도 인스턴스)
    model = LogisticRegression()
    model.fit(X, y)
    with open(model_path, "wb") as f:
        pickle.dump(model, f)
    return model


class QueryLimiter:
    """실제 API의 쿼리 예산 제약을 흉내낸다(레이트리밋 방어의 기반이 되는 카운터)."""

    def __init__(self, model, budget: int = 500):
        self.model = model
        self.budget = budget
        self.used = 0

    def predict_proba(self, X):
        if self.used + len(X) > self.budget:
            raise RuntimeError(f"query budget exceeded: used={self.used}, requested={len(X)}, budget={self.budget}")
        self.used += len(X)
        return self.model.predict_proba(X)


if __name__ == "__main__":
    train_and_save()
    print("victim 모델 학습 완료: victim.pkl")
