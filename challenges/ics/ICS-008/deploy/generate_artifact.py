"""
ICS-008 배포 생성기 - BACnet/IP 트래픽 로그(bacnet_traffic.jsonl) 합성.

정상 BMS 워크스테이션(10.70.0.10)의 ReadProperty(service 12) 사이에, 무단 장치가 냉방 제어
객체(analog-output, CRAC 급기온도 setpoint)에 WriteProperty(service 15)를 priority 8 이상
(수동 오버라이드)으로 내려 냉방을 끈 사보타주가 숨어 있다. 팀별 공격자 IP/토큰/flag가 HMAC 결정.
탐지: object_type=analog-output 에 대한 WriteProperty(service 15)를 정상 BMS가 아닌 출발지에서 찾음.
note(base64) 토큰을 공격자 IP로 XOR 복호하면 flag.
"""
import base64
import hashlib
import hmac
import json
import os
import random
import sys

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "ics008-dev-secret")
LEGIT_BMS = "10.70.0.10"
COOLING_OBJ = "analog-output"   # CRAC 급기온도 setpoint
WRITE_SERVICE = 15              # WriteProperty


def _hmac(tag, team, n): return hmac.new(CHALLENGE_SECRET.encode(), f"{tag}:{team}".encode(), hashlib.sha256).hexdigest()[:n]
def dynamic_flag(team): return f"flag{{bacnet_priority_override_{_hmac('ICS-008', team, 12)}}}"
def attacker_ip(team): return f"10.70.0.{int(_hmac('ICS-008-ip', team, 4), 16) % 200 + 30}"
def _xor(d, k): return bytes(b ^ k[i % len(k)] for i, b in enumerate(d))
def token_b64(team): return base64.b64encode(_xor(dynamic_flag(team).encode(), attacker_ip(team).encode())).decode()


def build(team):
    rng = random.Random(int(_hmac("ICS-008-seed", team, 8), 16))
    rows = []
    ts = 1_700_000_000.0
    objs = ["analog-input", "analog-value", "binary-input", "analog-output"]
    # 정상 BMS의 주기적 ReadProperty 폴링
    for _ in range(58):
        ts += rng.uniform(0.5, 2.0)
        rows.append({"ts": round(ts, 3), "src": LEGIT_BMS, "dst": "10.70.0.40",
                     "bacnet_service": 12, "service_name": "ReadProperty",
                     "object_type": rng.choice(objs), "object_instance": rng.randint(1, 12),
                     "property": "present-value", "priority": None, "note": ""})
    # 사보타주: rogue 장치가 냉방 setpoint 객체에 WriteProperty priority 8(수동 오버라이드)
    rows.append({"ts": round(ts + rng.uniform(5, 30), 3), "src": attacker_ip(team), "dst": "10.70.0.40",
                 "bacnet_service": WRITE_SERVICE, "service_name": "WriteProperty",
                 "object_type": COOLING_OBJ, "object_instance": 3, "property": "present-value",
                 "priority": 8, "note": token_b64(team)})
    # 미끼: 정상 BMS의 WriteProperty(냉방 아닌 조명 binary-output, 정상 우선순위 16)
    for _ in range(3):
        ts += rng.uniform(0.5, 2.0)
        rows.append({"ts": round(ts, 3), "src": LEGIT_BMS, "dst": "10.70.0.40",
                     "bacnet_service": WRITE_SERVICE, "service_name": "WriteProperty",
                     "object_type": "binary-output", "object_instance": rng.randint(1, 6),
                     "property": "present-value", "priority": 16, "note": ""})
    rng.shuffle(rows)
    return rows


def main():
    team = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    out = os.path.join(os.path.dirname(__file__), "bacnet_traffic.jsonl")
    with open(out, "w") as f:
        for r in build(team):
            f.write(json.dumps(r) + "\n")
    print(f"생성 완료: bacnet_traffic.jsonl (team={team}, attacker={attacker_ip(team)})")


if __name__ == "__main__":
    main()
