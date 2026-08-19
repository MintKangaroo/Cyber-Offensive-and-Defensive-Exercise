"""DET-013 배포 — 위성 TT&C(CCSDS) 무단 자세제어 안전해제 업링크가 섞인 로그 + 정상 로그 생성.

attack_log: protocol=ccsds AND command=DISABLE_ATTITUDE_SAFETY 동시충족(무단 SIS 해제 업링크).
normal_log: 각 조건을 '하나씩만' 충족하는 유사 트래픽 —
  (a) protocol=ccsds 이지만 정상 커맨드(PING/SET_ATTITUDE/ENABLE_ATTITUDE_SAFETY/하우스키핑)
  (b) command=DISABLE_ATTITUDE_SAFETY 이지만 지상 변경관리 감사 로그(protocol=audit)
따라서 단일조건 규칙은 오탐하고, AND 결합 규칙만 무오탐. 실제 SIEM DetectionEngine이 채점.
트윈이 발행하는 SIEM access 로그 필드(raw.protocol/raw.command/raw.apid)를 그대로 모사한다.
"""
import json
import time


def _evt(raw: dict, ts: float) -> dict:
    return {"source_type": "twin", "asset": "ground_station", "timestamp": ts, "raw": raw}


def generate_attack_log(path: str) -> None:
    t0 = time.time()
    rows = [
        _evt({"protocol": "ccsds", "apid": 100, "command": "PING", "method": "CCSDS"}, t0),
        _evt({"protocol": "ccsds", "apid": 100, "command": "DISABLE_ATTITUDE_SAFETY",
              "method": "CCSDS", "safety_impact": "attitude_safety_disabled",
              "src": "203.0.113.88"}, t0 + 4),
        _evt({"protocol": "ccsds", "apid": 100, "command": "SET_THRUSTER",
              "method": "CCSDS", "src": "203.0.113.88"}, t0 + 6),
        _evt({"protocol": "ccsds", "apid": 100, "command": "DISABLE_ATTITUDE_SAFETY",
              "method": "CCSDS", "safety_impact": "attitude_safety_disabled",
              "src": "203.0.113.88"}, t0 + 9),
    ]
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def generate_normal_log(path: str) -> None:
    t0 = time.time()
    rows = [
        # (a) 프로토콜만 같은 정상 CCSDS 커맨드 — protocol=ccsds 만 매칭
        _evt({"protocol": "ccsds", "apid": 100, "command": "PING", "method": "CCSDS"}, t0),
        _evt({"protocol": "ccsds", "apid": 100, "command": "SET_ATTITUDE", "method": "CCSDS"}, t0 + 2),
        _evt({"protocol": "ccsds", "apid": 200, "command": "HOUSEKEEPING_TM", "method": "CCSDS"}, t0 + 4),
        _evt({"protocol": "ccsds", "apid": 100, "command": "ENABLE_ATTITUDE_SAFETY", "method": "CCSDS"}, t0 + 6),
        # (b) 커맨드 이름만 같은 지상 변경관리 감사 로그 — command 만 매칭(protocol 다름)
        _evt({"protocol": "audit", "command": "DISABLE_ATTITUDE_SAFETY",
              "actor": "operator1", "note": "scheduled maintenance window, dual-approved"}, t0 + 8),
    ]
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


if __name__ == "__main__":
    generate_attack_log("attack_log.jsonl")
    generate_normal_log("normal_log.jsonl")
    print("생성 완료: attack_log.jsonl, normal_log.jsonl")
