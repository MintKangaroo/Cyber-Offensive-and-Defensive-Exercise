"""DET-001 배포 - 포트스캔 로그 + 오탐 유발용 노이즈가 섞인 정상 로그 생성."""
import json
import random
import time


def generate_scan_log(path: str) -> None:
    """단일 src(10.13.37.66)가 60초 내 15개의 서로 다른 포트를 스캔."""
    t0 = time.time()
    ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 8080]
    with open(path, "w") as f:
        for i, port in enumerate(ports):
            f.write(json.dumps({
                "source_type": "zeek", "src": {"ip": "10.13.37.66"}, "dst": {"port": port},
                "timestamp": t0 + i * 2,
            }) + "\n")


def generate_noise_log(path: str, seed: int = 7) -> None:
    """여러 정상 사용자가 각자 소수의 포트(웹/DNS 등)만 사용 -> 임계를 넘지 않아야 함.
    단, 일부러 '살짝 애매한' 케이스도 하나 섞는다(동일 IP가 8개 포트 사용 - 임계 15 미만)."""
    random.seed(seed)
    t0 = time.time()
    events = []
    normal_ips = [f"10.50.0.{i}" for i in range(1, 20)]
    for i in range(50):
        events.append({
            "source_type": "zeek", "src": {"ip": random.choice(normal_ips)},
            "dst": {"port": random.choice([80, 443, 53])}, "timestamp": t0 + i * random.uniform(1, 5),
        })
    # 애매한 케이스: 한 IP가 8개 포트 사용(스캔은 아니지만 다양한 서비스 이용 - 임계 15 미만이라 안전)
    borderline_ip = "10.50.0.99"
    for i, port in enumerate([80, 443, 53, 22, 8080, 3000, 5000, 9000]):
        events.append({
            "source_type": "zeek", "src": {"ip": borderline_ip}, "dst": {"port": port},
            "timestamp": t0 + 100 + i * 3,
        })
    with open(path, "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")


if __name__ == "__main__":
    generate_scan_log("scan_log.jsonl")
    generate_noise_log("noise_log.jsonl")
    print("생성 완료: scan_log.jsonl, noise_log.jsonl")
