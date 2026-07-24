"""DET-006 배포 - DGA(도메인 생성 알고리즘) 조회가 담긴 로그 + 정상 로그 생성.

attack_log.jsonl: 감염 호스트 한 대가 짧은 시간에 무작위처럼 보이는 서로 다른 도메인을 대량
조회(DGA C2 rendezvous). normal_log.jsonl: 정상 호스트들은 소수의 도메인만 조회(임계 미만),
경계 케이스로 캐시 워밍 호스트가 여러 도메인을 조회하지만 임계보다 적게.
"""
import hashlib
import json
import time


def _evt(ip: str, query: str, ts: float) -> dict:
    return {"source_type": "twin", "src": {"ip": ip}, "raw": {"query": query}, "timestamp": ts}


def _dga(seed: int) -> str:
    h = hashlib.sha256(str(seed).encode()).hexdigest()[:12]
    return f"{h}.example"


def generate_attack_log(path: str) -> None:
    t0 = time.time()
    rows = [_evt("10.31.31.31", _dga(i), t0 + i * 2) for i in range(25)]   # 25개 서로 다른 DGA 도메인
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def generate_normal_log(path: str) -> None:
    t0 = time.time()
    common = ["google.com", "cloudflare.com", "github.com", "microsoft.com", "ubuntu.com"]
    rows = []
    i = 0
    # 정상 호스트들: 각자 소수 도메인만
    for host in ["10.0.4.5", "10.0.4.6", "10.0.4.7"]:
        for dom in common[:3]:
            rows.append(_evt(host, dom, t0 + i)); i += 1
    # 경계 케이스: 캐시 워밍 호스트가 8개 도메인 조회(임계 20 미만이라 안전)
    for j, dom in enumerate(common + ["apple.com", "amazon.com", "netflix.com"]):
        rows.append(_evt("10.0.4.9", dom, t0 + 100 + j)); i += 1
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


if __name__ == "__main__":
    generate_attack_log("attack_log.jsonl")
    generate_normal_log("normal_log.jsonl")
    print("생성 완료: attack_log.jsonl, normal_log.jsonl")
