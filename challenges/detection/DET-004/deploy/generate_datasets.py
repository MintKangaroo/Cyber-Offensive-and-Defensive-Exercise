"""DET-004 배포 - C2 비콘(주기적 연결)이 담긴 로그 + 정상 로그 생성.

attack_log.jsonl: 감염 호스트가 C2로 정확히 300초 간격으로 6회 접속(jitter≈0).
normal_log.jsonl: (1) 내부 폴러가 allowlist 목적지(10.0.0.53)로 규칙적 접속하지만 allowlist라
탐지 제외, (2) 나머지는 불규칙 트래픽이라 주기성 임계를 넘지 않음 → 오탐 없음.
"""
import json
import time


def _evt(src: str, dst: str, ts: float) -> dict:
    return {"source_type": "twin", "src": {"ip": src}, "dst": {"ip": dst}, "timestamp": ts}


def generate_attack_log(path: str) -> None:
    t0 = time.time()
    rows = [_evt("10.20.20.20", "203.0.113.99", t0 + i * 300) for i in range(6)]   # 등간격 비콘
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def generate_normal_log(path: str) -> None:
    t0 = time.time()
    rows = []
    # (1) allowlist 목적지로의 규칙적 폴링(정상) — allowlist라 제외되어야 함
    rows += [_evt("10.0.1.5", "10.0.0.53", t0 + i * 60) for i in range(6)]
    # (2) 불규칙 정상 트래픽(주기성 낮음, 관측 수 부족)
    offsets = [(("10.0.1.7", "93.184.216.34"), 5), (("10.0.1.7", "1.1.1.1"), 33),
               (("10.0.1.8", "140.82.112.3"), 71), (("10.0.1.9", "8.8.8.8"), 120),
               (("10.0.1.7", "93.184.216.34"), 205), (("10.0.1.8", "151.101.1.69"), 260)]
    for (src, dst), off in offsets:
        rows.append(_evt(src, dst, t0 + off))
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


if __name__ == "__main__":
    generate_attack_log("attack_log.jsonl")
    generate_normal_log("normal_log.jsonl")
    print("생성 완료: attack_log.jsonl, normal_log.jsonl")
