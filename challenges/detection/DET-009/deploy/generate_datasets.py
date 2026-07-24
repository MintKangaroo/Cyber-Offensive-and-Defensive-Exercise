"""DET-009 배포 - APT low-and-slow 비콘 + 대량 잡음 + 다중 정상폴링 로그 생성.

attack_log.jsonl:
  - 저속 비콘: 10.30.30.30 -> 198.51.100.77, 간격 ≈1800초(지터 소폭), 8회.
    span ≈ 12600초 → window_sec 를 넉넉히(≥14000) 넓혀야 8회가 한 윈도우에 들어온다.
  - 잡음: 같은 감염 host 가 여러 목적지로 산발 접속(각 (src,dst) 쌍은 관측수 부족/불규칙).
normal_log.jsonl:
  - 정상 규칙 폴링(내부 DNS/NTP/외부 모니터링) → allowlist 로 제외되어야 함.
  - 불규칙 잡음(각 쌍 관측수 < 임계) → 오탐 없음.
"""
import json
import random

T0 = 1_700_000_000.0  # 결정론적 기준시각(고정 seed 로 재현 가능)


def _evt(src: str, dst: str, ts: float) -> dict:
    return {"source_type": "twin", "src": {"ip": src}, "dst": {"ip": dst}, "timestamp": round(ts, 2)}


def generate_attack_log(path: str) -> None:
    rng = random.Random(9009)
    rows = []

    # 저속 비콘(1800초 주기, 소폭 지터) 8회 → CV(지터) ≈ 0.02 로 임계 미만
    beacon_intervals = [1800, 1772, 1831, 1799, 1765, 1842, 1788]  # 7개 간격 → 8회 관측
    t = T0
    rows.append(_evt("10.30.30.30", "198.51.100.77", t))
    for iv in beacon_intervals:
        t += iv
        rows.append(_evt("10.30.30.30", "198.51.100.77", t))

    # 잡음: 같은 감염 host 가 여러 목적지로 산발 접속(각 쌍 관측수 5 미만, 불규칙)
    noise_dsts = ["8.8.8.8", "1.1.1.1", "93.184.216.34", "140.82.112.3",
                  "151.101.1.69", "203.0.113.5", "192.0.2.44", "198.51.100.9"]
    for _ in range(60):
        dst = rng.choice(noise_dsts)
        ts = T0 + rng.uniform(0, 13000)
        rows.append(_evt("10.30.30.30", dst, ts))
    # 다른 잡음 호스트들도 산발
    for _ in range(30):
        src = f"10.30.30.{rng.randint(31, 60)}"
        dst = rng.choice(noise_dsts)
        ts = T0 + rng.uniform(0, 13000)
        rows.append(_evt(src, dst, ts))

    rows.sort(key=lambda r: r["timestamp"])
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def generate_normal_log(path: str) -> None:
    rng = random.Random(4004)
    rows = []

    # (1) 정상 규칙 폴링 → allowlist 대상(넓은 window 에서도 제외되어야 함)
    for i in range(12):
        rows.append(_evt("10.0.1.10", "10.0.0.53", T0 + i * 600))     # 내부 DNS
    for i in range(10):
        rows.append(_evt("10.0.1.11", "10.0.0.123", T0 + i * 900))    # 내부 NTP
    for i in range(9):
        rows.append(_evt("10.0.1.12", "198.51.100.10", T0 + i * 1200))  # 외부 모니터링

    # (2) 불규칙 정상 잡음(각 (src,dst) 관측수 < 임계, 지터 큼)
    noise_dsts = ["8.8.8.8", "1.1.1.1", "93.184.216.34", "140.82.112.3", "151.101.1.69"]
    for _ in range(50):
        src = f"10.0.1.{rng.randint(20, 40)}"
        dst = rng.choice(noise_dsts)
        ts = T0 + rng.uniform(0, 13000)
        rows.append(_evt(src, dst, ts))

    rows.sort(key=lambda r: r["timestamp"])
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


if __name__ == "__main__":
    generate_attack_log("attack_log.jsonl")
    generate_normal_log("normal_log.jsonl")
    print("생성 완료: attack_log.jsonl, normal_log.jsonl")
