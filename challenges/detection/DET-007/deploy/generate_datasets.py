"""DET-007 배포 - BACnet 냉방 오버라이드 사보타주가 섞인 BAS 로그 + 정상 로그 생성.

attack_log.jsonl: 냉방 제어 객체(analog-output)에 대한 WriteProperty(service 15) 요청(사보타주).
normal_log.jsonl: analog-output에 대한 ReadProperty(service 12)와 조명(binary-output)에 대한
정상 WriteProperty(service 15)만 — 즉 (service 15 AND analog-output) 조합은 절대 없어야 오탐이
안 난다. service 하나 또는 object_type 하나만 보는 규칙은 여기서 오탐한다.
"""
import json
import time


def _evt(service, service_name, object_type, ts, src="10.70.0.30", priority=None):
    return {"source_type": "twin", "timestamp": ts,
            "raw": {"proto": "bacnet", "src": src, "bacnet_service": service,
                    "service_name": service_name, "object_type": object_type,
                    "property": "present-value", "priority": priority}}


def generate_attack_log(path: str) -> None:
    t0 = time.time()
    rows = [
        _evt(12, "ReadProperty", "analog-input", t0),                      # 정상 폴링(잡히면 안 됨)
        _evt(15, "WriteProperty", "analog-output", t0 + 1, src="10.70.0.66", priority=8),  # 사보타주
        _evt(12, "ReadProperty", "binary-input", t0 + 2),
        _evt(15, "WriteProperty", "analog-output", t0 + 3, src="10.70.0.66", priority=8),  # 사보타주 2
    ]
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def generate_normal_log(path: str) -> None:
    t0 = time.time()
    rows = [
        _evt(12, "ReadProperty", "analog-output", t0),           # analog-output 이지만 read → 정상
        _evt(15, "WriteProperty", "binary-output", t0 + 1, priority=16),  # write 이지만 조명 → 정상
        _evt(12, "ReadProperty", "analog-value", t0 + 2),
        _evt(15, "WriteProperty", "binary-output", t0 + 3, priority=16),  # 조명 스케줄 정상
        _evt(12, "ReadProperty", "analog-output", t0 + 4),       # 냉방 setpoint read → 정상
    ]
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


if __name__ == "__main__":
    generate_attack_log("attack_log.jsonl")
    generate_normal_log("normal_log.jsonl")
    print("생성 완료: attack_log.jsonl, normal_log.jsonl")
