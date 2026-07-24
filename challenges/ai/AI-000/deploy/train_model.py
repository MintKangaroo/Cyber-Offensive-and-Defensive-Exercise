"""
AI-000 배포 - 합성 데이터로 피싱 URL 탐지기(로지스틱 회귀) 학습.
특징 6개: [length, dot_count, special_char_count, has_at, is_ip_like, has_phishing_keyword]
"""
import json
import pickle
import numpy as np
from sklearn.linear_model import LogisticRegression

FEATURE_NAMES = ["length", "dot_count", "special_char_count", "has_at", "is_ip_like", "has_keyword"]


def make_synthetic_dataset(n_per_class: int = 200, seed: int = 0):
    rng = np.random.RandomState(seed)
    X, y = [], []
    # 정상 URL 특징(짧고, 점 적고, 특수문자 적고, 키워드 없음)
    for _ in range(n_per_class):
        X.append([
            rng.uniform(10, 30), rng.uniform(1, 3), rng.uniform(0, 3),
            0, 0, rng.choice([0, 0, 0, 1]),
        ])
        y.append(0)
    # 악성 URL 특징(길고, 점 많고, 특수문자 많고, 키워드 있음)
    for _ in range(n_per_class):
        X.append([
            rng.uniform(40, 90), rng.uniform(4, 8), rng.uniform(5, 15),
            rng.choice([0, 1]), rng.choice([0, 1]), 1,
        ])
        y.append(1)
    return np.array(X), np.array(y)


def train_and_save(model_path: str = "detector.pkl") -> LogisticRegression:
    X, y = make_synthetic_dataset()
    model = LogisticRegression()
    model.fit(X, y)
    with open(model_path, "wb") as f:
        pickle.dump(model, f)
    return model


def make_malicious_sample(model_path: str = "detector.pkl", out_path: str = "malicious_sample.json"):
    """의도적으로 강하게 악성으로 분류되는 샘플 하나를 생성해 아티팩트로 제공."""
    sample = {"length": 75, "dot_count": 6, "special_char_count": 10, "has_at": 1, "is_ip_like": 1, "has_keyword": 1}
    with open(out_path, "w") as f:
        json.dump(sample, f, indent=2)
    return sample


if __name__ == "__main__":
    model = train_and_save()
    sample = make_malicious_sample()
    score = model.predict_proba([[sample[k] for k in FEATURE_NAMES]])[0][1]
    print(f"모델 학습 완료. 악성 샘플 malicious_score={score:.3f} (0.5 이상이면 정상 분류)")
