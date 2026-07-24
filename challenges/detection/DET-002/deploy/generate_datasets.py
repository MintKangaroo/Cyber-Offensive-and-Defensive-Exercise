"""DET-002 배포 - SQLi 공격이 섞인 웹 접근 로그 + 정상 로그 생성.

attack_log.jsonl: 정상 요청 사이에 SQL 인젝션 시도(UNION SELECT)가 섞임.
normal_log.jsonl: 정상 요청만(일부러 SQL 키워드가 들어간 정상 검색어도 섞어 오탐 유발 시도).
"""
import json
import time


def _evt(uri: str, ts: float) -> dict:
    return {"source_type": "twin", "raw": {"uri": uri}, "timestamp": ts}


def generate_attack_log(path: str) -> None:
    t0 = time.time()
    rows = [
        "/products?id=10",
        "/search?q=laptop",
        "/products?id=10 UNION SELECT username,password FROM users--",   # SQLi
        "/login",
        "/products?id=5",
    ]
    with open(path, "w") as f:
        for i, uri in enumerate(rows):
            f.write(json.dumps(_evt(uri, t0 + i)) + "\n")


def generate_normal_log(path: str) -> None:
    t0 = time.time()
    rows = [
        "/products?id=1",
        "/search?q=how to select a union credit card",   # 'select'/'union' 단어가 있지만 SQLi 아님(오탐 유발)
        "/cart/add?item=42",
        "/blog/2024/database-tuning",
        "/search?q=UNION jobs",
        "/account/settings",
    ]
    with open(path, "w") as f:
        for i, uri in enumerate(rows):
            f.write(json.dumps(_evt(uri, t0 + i)) + "\n")


if __name__ == "__main__":
    generate_attack_log("attack_log.jsonl")
    generate_normal_log("normal_log.jsonl")
    print("생성 완료: attack_log.jsonl, normal_log.jsonl")
