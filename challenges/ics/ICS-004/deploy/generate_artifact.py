"""
ICS-004 배포 생성기 - IEC 60870-5-104 트래픽 로그(iec104_log.jsonl) 합성.

정상 SCADA 마스터(10.40.0.3)의 감시 방향 ASDU(M_SP_NA_1=1, 자발 COT=3) 사이에, 무단 제어국이
보호 IOA(차단기, ioa=7)에 단일명령 C_SC_NA_1(type 45, 활성화 COT=6)을 내린 사보타주 1건이
숨어 있다. 팀별 공격자 IP/토큰/flag가 HMAC 결정. note(base64) 토큰을 공격자 IP로 XOR 복호하면 flag.
"""
import base64
import hashlib
import hmac
import json
import os
import random
import sys

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "ics004-dev-secret")
LEGIT_MASTER = "10.40.0.3"
CB_IOA = 7
CONTROL_TYPES = {45, 46, 47, 48, 49, 50, 51}  # C_SC/C_DC/C_RC/C_SE/C_BO


def _hmac(tag, team, n): return hmac.new(CHALLENGE_SECRET.encode(), f"{tag}:{team}".encode(), hashlib.sha256).hexdigest()[:n]
def dynamic_flag(team): return f"flag{{iec104_command_injection_{_hmac('ICS-004', team, 12)}}}"
def attacker_ip(team): return f"10.40.0.{int(_hmac('ICS-004-ip', team, 4), 16) % 200 + 30}"
def _xor(d, k): return bytes(b ^ k[i % len(k)] for i, b in enumerate(d))
def token_b64(team): return base64.b64encode(_xor(dynamic_flag(team).encode(), attacker_ip(team).encode())).decode()


def build(team):
    rng = random.Random(int(_hmac("ICS-004-seed", team, 8), 16))
    rows = []
    ts = 1_700_000_000.0
    for _ in range(60):
        ts += rng.uniform(0.5, 2.0)
        rows.append({"ts": round(ts, 3), "src": LEGIT_MASTER, "dst": "10.40.0.20",
                     "asdu_type": 1, "cot": 3, "ioa": rng.choice([100, 101, 102]),
                     "value": rng.choice([0, 1]), "note": ""})
    # 사보타주: rogue 제어국이 CB에 C_SC_NA_1(활성화)
    rows.append({"ts": round(ts + rng.uniform(5, 30), 3), "src": attacker_ip(team), "dst": "10.40.0.20",
                 "asdu_type": 45, "cot": 6, "ioa": CB_IOA, "value": 1, "note": token_b64(team)})
    # 미끼: 정상 마스터의 제어(보호 IOA 아님)
    for _ in range(3):
        ts += rng.uniform(0.5, 2.0)
        rows.append({"ts": round(ts, 3), "src": LEGIT_MASTER, "dst": "10.40.0.20",
                     "asdu_type": 45, "cot": 6, "ioa": rng.choice([200, 201]), "value": 1, "note": ""})
    rng.shuffle(rows)
    return rows


def main():
    team = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    out = os.path.join(os.path.dirname(__file__), "iec104_log.jsonl")
    with open(out, "w") as f:
        for r in build(team):
            f.write(json.dumps(r) + "\n")
    print(f"생성 완료: iec104_log.jsonl (team={team}, attacker={attacker_ip(team)})")


if __name__ == "__main__":
    main()
