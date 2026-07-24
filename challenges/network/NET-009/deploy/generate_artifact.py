"""NET-009 배포 - 팀별 OT 사보타주 Modbus 트레이스(ot_trace.json) 생성.

단계:
  1) 인가되지 않은 rogue_ip 가 쓰기 명령 발행(assets.authorized 에 없음).
  2) rogue_ip 가 커버트 레지스터에 반복 쓰기(정상 공정 레지스터 40001..40010 밖).
  3) 커버트 레지스터 value 들의 하위 바이트 = base64(flag) 각 문자. 시간순 이어붙여 디코드하면 flag.

모든 값이 팀별 HMAC 로 결정론적. IP는 RFC5737(TEST-NET) 대역.
"""
import base64
import hashlib
import hmac
import json
import os
import random
import sys

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "net009-dev-secret")

BASE_TS = 1_700_000_000
AUTHORIZED = ["10.10.0.5", "10.10.0.6"]      # HMI, EWS
PLC_IP = "10.10.0.20"
PROCESS_REGS = list(range(40001, 40011))     # 정상 공정 레지스터
SAFETY_REG = 40020                           # 안전 세트포인트(사보타주 대상)

FUNC_READ, FUNC_WRITE1, FUNC_WRITE16 = 3, 6, 16


def dynamic_flag(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"NET-009:{team_id}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"flag{{ot_sabotage_{sig}}}"


def _rng(team_id: str) -> random.Random:
    seed = int(hmac.new(CHALLENGE_SECRET.encode(), f"NET-009-rng:{team_id}".encode(),
                        hashlib.sha256).hexdigest(), 16)
    return random.Random(seed)


def rogue_ip(team_id: str, rng: random.Random) -> str:
    return f"10.10.0.{rng.randint(60, 250)}"


def covert_register(team_id: str, rng: random.Random) -> int:
    return rng.choice([40088, 40099, 40077, 40066])


def build_trace(team_id: str) -> dict:
    rng = _rng(team_id)
    flag = dynamic_flag(team_id)
    rip = rogue_ip(team_id, rng)
    creg = covert_register(team_id, rng)

    events = []
    ts = BASE_TS

    def push(src, func, reg, val):
        nonlocal ts
        ts += rng.randint(1, 4)
        events.append({"ts": ts, "src_ip": src, "dst_ip": PLC_IP,
                       "unit_id": 1, "func": func, "register": reg, "value": val})

    # 정상 트래픽: HMI/EWS 가 공정 레지스터를 읽고 가끔 인가된 쓰기
    for _ in range(80):
        src = rng.choice(AUTHORIZED)
        reg = rng.choice(PROCESS_REGS)
        if rng.random() < 0.75:
            push(src, FUNC_READ, reg, 0)
        else:
            push(src, FUNC_WRITE1, reg, rng.randint(20, 80))   # 안전 범위 내

    # 공격 1: rogue 가 안전 세트포인트를 위험값으로 덮어씀(사보타주)
    push(rip, FUNC_WRITE1, SAFETY_REG, rng.randint(9000, 9999))

    # 공격 2: 커버트 레지스터에 base64(flag) 문자들을 하위 바이트로 실어 반복 쓰기
    payload = base64.b64encode(flag.encode()).decode()
    for c in payload:
        high = rng.randint(0, 60) << 8        # 상위 바이트는 잡음(하위만 유효)
        push(rip, FUNC_WRITE1, creg, high | ord(c))

    # rogue 가 정상 위장용으로 읽기도 몇 번
    for _ in range(5):
        push(rip, FUNC_READ, rng.choice(PROCESS_REGS), 0)

    events.sort(key=lambda e: e["ts"])
    return {
        "protocol": "modbus-tcp",
        "assets": {"plc": PLC_IP, "authorized": AUTHORIZED,
                   "process_registers": PROCESS_REGS, "safety_register": SAFETY_REG},
        "events": events,
    }


def generate(path: str, team_id: str) -> None:
    with open(path, "w") as f:
        json.dump(build_trace(team_id), f)


if __name__ == "__main__":
    team_id = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    generate("ot_trace.json", team_id)
    print(f"생성 완료: ot_trace.json (team={team_id})")
