"""
DET-000 배포 - 공격/정상 로그셋 생성기.
이 챌린지는 취약 서비스가 아니라 '탐지 룰 작성' 문제이므로, deploy 산출물은
attack_log.jsonl / normal_log.jsonl 두 데이터셋이다(11번 문서 표준의 artifacts에 대응).
"""
import json
import time
import random


def generate_attack_log(path: str) -> None:
    """동일 src(10.13.37.66)의 401 연속 10회를 60초 이내에 발생시킨다."""
    t0 = time.time()
    events = []
    for i in range(10):
        events.append({
            "source_type": "twin", "asset": "ground_station", "endpoint": "/api/login",
            "status": 401, "src": {"ip": "10.13.37.66"}, "timestamp": t0 + i * 5,
        })
    with open(path, "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")


def generate_normal_log(path: str, seed: int = 42) -> None:
    """여러 정상 사용자의 로그인 성공/실패가 섞인, 임계를 넘지 않는 정상 트래픽."""
    random.seed(seed)
    t0 = time.time()
    events = []
    ips = [f"10.50.0.{i}" for i in range(1, 15)]
    for i in range(30):
        events.append({
            "source_type": "twin", "asset": "ground_station", "endpoint": "/api/login",
            "status": random.choice([200, 200, 200, 401]),  # 가끔 실수로 틀리는 정도
            "src": {"ip": random.choice(ips)}, "timestamp": t0 + i * random.uniform(1, 10),
        })
    with open(path, "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")


if __name__ == "__main__":
    generate_attack_log("attack_log.jsonl")
    generate_normal_log("normal_log.jsonl")
    print("생성 완료: attack_log.jsonl, normal_log.jsonl")
