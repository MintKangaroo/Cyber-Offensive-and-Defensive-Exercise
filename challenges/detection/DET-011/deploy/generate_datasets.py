"""DET-011 배포 - S7comm 사보타주가 섞인 로그 + 정상 로그 생성.

attack_log: 판별 3조건 동시충족(사보타주). normal_log: 각 조건을 하나씩만 충족하는 정상 트래픽 —
따라서 단일조건 규칙은 오탐하고, AND 결합 규칙만 무오탐. 실제 SIEM DetectionEngine이 채점.
"""
import json
import time


def _evt(raw: dict, ts: float) -> dict:
    return {"source_type": "twin", "timestamp": ts, "raw": raw}


def generate_attack_log(path: str) -> None:
    t0 = time.time()
    rows = [
    _evt({"proto":"s7comm","s7_function":"READ_VAR","area":"DB","db_number":1,"op":"read"}, t0),
    _evt({"proto":"s7comm","s7_function":"WRITE_VAR","area":"DB","db_number":62,"op":"write","src":"10.85.0.66"}, t0+1),
    _evt({"proto":"s7comm","s7_function":"READ_VAR","area":"DB","db_number":10,"op":"read"}, t0+2),
    _evt({"proto":"s7comm","s7_function":"WRITE_VAR","area":"DB","db_number":62,"op":"write","src":"10.85.0.66"}, t0+3),
    ]
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def generate_normal_log(path: str) -> None:
    t0 = time.time()
    rows = [
    _evt({"proto":"s7comm","s7_function":"READ_VAR","area":"DB","db_number":62,"op":"read"}, t0),
    _evt({"proto":"s7comm","s7_function":"WRITE_VAR","area":"DB","db_number":10,"op":"write"}, t0+1),
    _evt({"proto":"s7comm","s7_function":"READ_VAR","area":"DB","db_number":20,"op":"read"}, t0+2),
    _evt({"proto":"s7comm","s7_function":"WRITE_VAR","area":"DB","db_number":20,"op":"write"}, t0+3),
    _evt({"proto":"s7comm","s7_function":"READ_VAR","area":"DB","db_number":62,"op":"read"}, t0+4),
    ]
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


if __name__ == "__main__":
    generate_attack_log("attack_log.jsonl")
    generate_normal_log("normal_log.jsonl")
    print("생성 완료: attack_log.jsonl, normal_log.jsonl")
