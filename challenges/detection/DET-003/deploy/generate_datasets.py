"""DET-003 배포 - 웹쉘 업로드→실행 시퀀스가 담긴 로그 + 정상 로그 생성.

attack_log.jsonl: 한 IP가 .php 파일 업로드 후 그 .php를 실행(웹쉘 킬체인).
normal_log.jsonl: 정상 업로드(이미지)와 정상 요청만 — 단일 IP가 '.php 업로드→.php 실행'을
동시에 하지 않으므로 시퀀스가 완성되지 않아야 한다(오탐 없음).
"""
import json
import time


def _evt(ip: str, uri: str, ts: float, file: str = "") -> dict:
    raw = {"uri": uri}
    if file:
        raw["file"] = file
    return {"source_type": "twin", "src": {"ip": ip}, "raw": raw, "timestamp": ts}


def generate_attack_log(path: str) -> None:
    t0 = time.time()
    atk = "10.66.66.66"
    rows = [
        _evt(atk, "/upload", t0, file="shell.php"),        # step1: .php 업로드
        _evt("10.0.0.7", "/products", t0 + 3),             # 잡음(다른 IP)
        _evt(atk, "/uploads/shell.php", t0 + 12),          # step2: 업로드한 .php 실행
    ]
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def generate_normal_log(path: str) -> None:
    t0 = time.time()
    rows = [
        _evt("10.0.0.11", "/upload", t0, file="avatar.jpg"),   # 정상 이미지 업로드(.php 아님)
        _evt("10.0.0.11", "/uploads/avatar.jpg", t0 + 8),      # 그 이미지 조회(.php 아님)
        _evt("10.0.0.12", "/app.php", t0 + 15),                # .php 요청이지만 업로드 이력 없음
        _evt("10.0.0.13", "/index.html", t0 + 20),
        _evt("10.0.0.14", "/upload", t0 + 25, file="report.pdf"),
        _evt("10.0.0.14", "/reports", t0 + 30),
    ]
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


if __name__ == "__main__":
    generate_attack_log("attack_log.jsonl")
    generate_normal_log("normal_log.jsonl")
    print("생성 완료: attack_log.jsonl, normal_log.jsonl")
