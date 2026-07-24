"""
AI-007 배포 - 합성 데이터로 악성코드 탐지 MLP를 학습(numpy 순수 구현, ML 프레임워크 불요).

AI-000(선형·특징공간 회피)의 상위판. 여기서는 **비선형 2층 MLP**를 직접 역전파로 학습하고,
서버가 입력에 L∞ 섭동 예산(epsilon)과 [0,1] 박스 제약을 강제한다. 따라서 단순히 특징 하나를
크게 낮추는 AI-000식 회피는 예산을 벗어나 거부된다. Red는 화이트박스(모델 가중치 공개)에서
**그래디언트 기반 반복 공격(PGD)** 으로 예산 안의 최소 섭동을 찾아 오분류를 유도해야 한다.

산출물:
  - model.npz : W1,b1,W2,b2 (+ 소스 샘플 x0, epsilon, 특징명)
결정적: 고정 seed + 고정 하이퍼파라미터로 학습 → 매 빌드 동일 가중치/소스/예산.
"""
import numpy as np

SEED = 20260724
D = 8            # 특징 차원
H = 16           # 은닉 유닛
EPOCHS = 800
LR = 0.1
WD = 2e-3        # L2 weight decay(과확신 완화 → 예산 안에서 회피 가능하게)
EPS = 0.12       # L∞ 섭동 예산(정규화 특징 [0,1] 기준)
SOURCE_TARGET_PROB = 0.85   # 소스 샘플을 경계 근처(강하게 malware지만 과확신 아님)로 선택

FEATURE_NAMES = [
    "entropy", "import_count", "section_count", "packed",
    "susp_api_ratio", "net_calls", "size_kb_norm", "signed",
]
BENIGN_MU = np.array([0.30, 0.35, 0.40, 0.05, 0.20, 0.25, 0.30, 0.85])
MALWARE_MU = np.array([0.80, 0.70, 0.65, 0.80, 0.80, 0.70, 0.70, 0.10])


def _softmax(z):
    z = z - z.max(axis=1, keepdims=True)
    e = np.exp(z)
    return e / e.sum(axis=1, keepdims=True)


def make_dataset(n_per_class=400, seed=SEED):
    rng = np.random.RandomState(seed)
    Xb = rng.normal(BENIGN_MU, 0.10, size=(n_per_class, D))
    Xm = rng.normal(MALWARE_MU, 0.10, size=(n_per_class, D))
    X = np.clip(np.vstack([Xb, Xm]), 0.0, 1.0)
    y = np.array([0] * n_per_class + [1] * n_per_class)  # 0=benign, 1=malware
    return X, y


def train(seed=SEED):
    rng = np.random.RandomState(seed)
    X, y = make_dataset(seed=seed)
    n = X.shape[0]
    Y = np.zeros((n, 2)); Y[np.arange(n), y] = 1.0

    W1 = rng.normal(0, 0.5, size=(D, H)); b1 = np.zeros(H)
    W2 = rng.normal(0, 0.5, size=(H, 2)); b2 = np.zeros(2)
    for _ in range(EPOCHS):
        z1 = X @ W1 + b1
        a1 = np.maximum(0, z1)                 # ReLU
        probs = _softmax(a1 @ W2 + b2)
        dlogits = (probs - Y) / n
        dW2 = a1.T @ dlogits + WD * W2; db2 = dlogits.sum(0)
        da1 = dlogits @ W2.T
        dz1 = da1 * (z1 > 0)
        dW1 = X.T @ dz1 + WD * W1; db1 = dz1.sum(0)
        W1 -= LR * dW1; b1 -= LR * db1
        W2 -= LR * dW2; b2 -= LR * db2

    pred = _softmax(np.maximum(0, X @ W1 + b1) @ W2 + b2).argmax(1)
    return W1, b1, W2, b2, (pred == y).mean()


def forward_prob(x, W1, b1, W2, b2):
    a1 = np.maximum(0, x @ W1 + b1)
    return _softmax(a1 @ W2 + b2)


def pick_source(W1, b1, W2, b2):
    """benign↔malware 평균을 보간해 malware_prob≈SOURCE_TARGET_PROB인 경계 근처 소스를 결정적 선택."""
    best = None
    for t in np.linspace(0.2, 1.0, 400):
        x = (1 - t) * BENIGN_MU + t * MALWARE_MU
        p = forward_prob(x[None, :], W1, b1, W2, b2)[0, 1]
        if p < 0.5:
            continue
        d = abs(p - SOURCE_TARGET_PROB)
        if best is None or d < best[2]:
            best = (x, p, d)
    return best[0], best[1]


def main(out_path="model.npz"):
    W1, b1, W2, b2, acc = train()
    x0, p_mal = pick_source(W1, b1, W2, b2)
    np.savez(out_path, W1=W1, b1=b1, W2=W2, b2=b2, x0=x0,
             eps=np.array(EPS), feature_names=np.array(FEATURE_NAMES))
    print(f"학습 완료 acc={acc:.3f}  소스 malware_prob={p_mal:.3f}  eps={EPS}")
    return out_path


if __name__ == "__main__":
    main()
