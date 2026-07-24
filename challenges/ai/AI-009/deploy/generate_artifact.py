"""AI-009 배포 - 적대적 회피 인시던트(evasion_incident.json) 생성.

로지스틱 회귀 탐지기(특징 6개)에 대한 전이 회피 공격을 재구성 가능한 형태로 합성:
  - 악성 시드 벡터 m (score>threshold).
  - 공격자는 가중치 큰 특징 몇 개를 낮춰 최소 L0 섭동으로 회피(score<threshold)한 쿼리 E 생성.
  - E 는 시드와 인덱스 집합 S 에서만 다르다. S 를 콤마로 이은 문자열이 XOR 키.
  - E.sig = XOR(flag, key) 의 hex. 나머지 쿼리는 시드와 무관한 잡음(양성/악성 섞임).

모든 값이 팀별 HMAC 로 결정론적.
"""
import hashlib
import hmac
import json
import math
import os
import random
import sys

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "ai009-dev-secret")
NFEAT = 6
THRESHOLD = 0.5


def dynamic_flag(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"AI-009:{team_id}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"flag{{transfer_evasion_{sig}}}"


def _rng(team_id: str) -> random.Random:
    seed = int(hmac.new(CHALLENGE_SECRET.encode(), f"AI-009-rng:{team_id}".encode(),
                        hashlib.sha256).hexdigest(), 16)
    return random.Random(seed)


def _sigmoid(z: float) -> float:
    return 1.0 / (1.0 + math.exp(-z))


def _score(w, b, x):
    return _sigmoid(sum(wi * xi for wi, xi in zip(w, x)) + b)


def _xor_repeat(data: bytes, key: bytes) -> bytes:
    return bytes(v ^ key[i % len(key)] for i, v in enumerate(data))


def _r3(rng, lo, hi):
    return round(rng.uniform(lo, hi), 3)


def build_incident(team_id: str) -> dict:
    rng = _rng(team_id)
    flag = dynamic_flag(team_id)

    # 양의 가중치 모델(특징이 높을수록 악성). bias 는 시드가 확실히 악성이 되도록.
    weights = [round(rng.uniform(1.0, 3.0), 3) for _ in range(NFEAT)]
    bias = -0.5 * sum(weights)

    # 악성 시드: 모든 특징이 높음 -> score > 0.5
    seed = [_r3(rng, 0.75, 1.0) for _ in range(NFEAT)]
    assert _score(weights, bias, seed) > THRESHOLD, "시드가 악성이 아님"

    # 최소 섭동: 가중치 큰 상위 3개 특징을 0 근처로 낮춰 회피
    top = sorted(range(NFEAT), key=lambda i: weights[i], reverse=True)[:3]
    S = sorted(top)
    evade = list(seed)
    for i in S:
        evade[i] = _r3(rng, 0.0, 0.05)
    assert _score(weights, bias, evade) < THRESHOLD, "회피 실패"

    # 키 = 정렬된 섭동 인덱스 문자열, sig = XOR(flag, key) 의 hex
    key = ",".join(str(i) for i in S)
    sig = _xor_repeat(flag.encode(), key.encode()).hex()

    queries = []
    qid = 1000

    def push(features, extra=None):
        nonlocal qid
        qid += 1
        q = {"id": f"q{qid}", "features": [round(f, 3) for f in features],
             "score": round(_score(weights, bias, features), 4)}
        if extra:
            q.update(extra)
        queries.append(q)
        return q["id"]

    # 잡음 쿼리: 시드와 무관한 랜덤 벡터(양성/악성 섞임). 모든 특징이 시드와 다름.
    for _ in range(40):
        push([_r3(rng, 0.0, 1.0) for _ in range(NFEAT)])

    # 회피 쿼리(정답): 시드와 S 에서만 다름
    evasion_id = push(evade, {"sig": sig})

    rng.shuffle(queries)
    return {
        "model": {"type": "logreg", "weights": weights, "bias": round(bias, 3),
                  "threshold": THRESHOLD, "features": [f"f{i}" for i in range(NFEAT)]},
        "malicious_seed": [round(f, 3) for f in seed],
        "note": "공격자가 던진 쿼리 로그. sig 필드는 일부 쿼리에만 존재.",
        "queries": queries,
        # 검증 편의를 위한 비공개 힌트는 넣지 않음(evasion_id 는 solve 가 스스로 찾음)
        "_debug_evasion_id": evasion_id,  # solve 는 사용하지 않음(자체 재구성). 참고용.
    }


def generate(path: str, team_id: str) -> None:
    data = build_incident(team_id)
    data.pop("_debug_evasion_id", None)
    with open(path, "w") as f:
        json.dump(data, f)


if __name__ == "__main__":
    team_id = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    generate("evasion_incident.json", team_id)
    print(f"생성 완료: evasion_incident.json (team={team_id})")
