"""DET-008 배포 - Foundation Fieldbus MODE_BLK O/S 사보타주가 섞인 H1 로그 + 정상 로그 생성.

attack_log.jsonl: 안전 PID 블록(FIC-201)에 MODE_BLK.TARGET=O/S(Out of Service) write(사보타주).
normal_log.jsonl: setpoint(SP) write, MODE_BLK를 AUTO로 되돌리는 정상 운전복귀, MODE_BLK read
만 — 즉 (param=MODE_BLK AND op=write AND value=OOS) 조합은 절대 없어야 오탐이 안 난다.
param 하나 또는 op 하나만 보는 규칙은 여기서 오탐한다.
"""
import json
import time


def _evt(block, param, op, value, ts, src_addr="0x11"):
    return {"source_type": "twin", "timestamp": ts,
            "raw": {"proto": "ff-h1", "src_addr": src_addr, "block": block,
                    "param": param, "op": op, "value": value}}


def generate_attack_log(path: str) -> None:
    t0 = time.time()
    rows = [
        _evt("AI-101", "PV", "read", 42.1, t0),                              # 정상 폴링
        _evt("FIC-201", "MODE_BLK", "write", "OOS", t0 + 1, src_addr="0x2a"),  # 사보타주
        _evt("PID-301", "SP", "write", 55.0, t0 + 2),
        _evt("FIC-201", "MODE_BLK", "write", "OOS", t0 + 3, src_addr="0x2a"),  # 사보타주 2
    ]
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def generate_normal_log(path: str) -> None:
    t0 = time.time()
    rows = [
        _evt("PID-301", "SP", "write", 60.0, t0),                # SP write → param 불일치, 정상
        _evt("FIC-201", "MODE_BLK", "write", "AUTO", t0 + 1),    # 운전복귀(AUTO) → value 불일치, 정상
        _evt("FIC-201", "MODE_BLK", "read", "AUTO", t0 + 2),     # MODE_BLK read → op 불일치, 정상
        _evt("AO-401", "OUT", "write", 30.0, t0 + 3),            # 출력 write → param 불일치
        _evt("FIC-201", "MODE_BLK", "write", "MAN", t0 + 4),     # 수동전환(MAN) → value 불일치, 정상
    ]
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


if __name__ == "__main__":
    generate_attack_log("attack_log.jsonl")
    generate_normal_log("normal_log.jsonl")
    print("생성 완료: attack_log.jsonl, normal_log.jsonl")
