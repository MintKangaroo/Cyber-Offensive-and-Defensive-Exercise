"""
ICS-005 배포 생성기 - Profinet DCP 트래픽 로그(profinet_dcp.jsonl) 합성.

정상 스테이션(plc-line-a)의 DCP Ident 응답 사이에, 무단 MAC이 같은 station_name을 다른 IP로
DCP-Set 하는 신원 스푸핑(MITM)이 숨어 있다. 팀별 rogue MAC/토큰/flag가 HMAC 결정.
탐지: 동일 station_name을 정상 MAC이 아닌 출발지가 DCP-Set → 그 MAC이 공격자.
note(base64) 토큰을 rogue MAC으로 XOR 복호하면 flag.
"""
import base64
import hashlib
import hmac
import json
import os
import random
import sys

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요.")
LEGIT_MAC = "00:0e:cf:11:22:33"
TARGET_STATION = "plc-line-a"


def _hmac(tag, team, n): return hmac.new(CHALLENGE_SECRET.encode(), f"{tag}:{team}".encode(), hashlib.sha256).hexdigest()[:n]
def dynamic_flag(team): return f"flag{{profinet_dcp_spoof_{_hmac('ICS-005', team, 12)}}}"


def attacker_mac(team):
    h = _hmac("ICS-005-mac", team, 6)
    return "de:ad:" + ":".join(h[i:i+2] for i in range(0, 8, 2))


def _xor(d, k): return bytes(b ^ k[i % len(k)] for i, b in enumerate(d))
def token_b64(team): return base64.b64encode(_xor(dynamic_flag(team).encode(), attacker_mac(team).encode())).decode()


def build(team):
    rng = random.Random(int(_hmac("ICS-005-seed", team, 8), 16))
    rows = []
    ts = 1_700_000_000.0
    stations = [("plc-line-a", LEGIT_MAC, "10.50.0.11"), ("hmi-a", "00:0e:cf:44:55:66", "10.50.0.12"),
                ("io-dev-3", "00:0e:cf:77:88:99", "10.50.0.13")]
    for _ in range(50):
        ts += rng.uniform(0.5, 2.0)
        name, mac, ip = rng.choice(stations)
        rows.append({"ts": round(ts, 3), "src_mac": mac, "station_name": name, "ip": ip,
                     "dcp_service": "Ident.Rsp", "note": ""})
    # 스푸핑: rogue MAC이 TARGET_STATION을 다른 IP로 DCP-Set
    rows.append({"ts": round(ts + rng.uniform(5, 30), 3), "src_mac": attacker_mac(team),
                 "station_name": TARGET_STATION, "ip": "10.50.0.250",
                 "dcp_service": "Set.Req", "note": token_b64(team)})
    rng.shuffle(rows)
    return rows


def main():
    team = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    out = os.path.join(os.path.dirname(__file__), "profinet_dcp.jsonl")
    with open(out, "w") as f:
        for r in build(team):
            f.write(json.dumps(r) + "\n")
    print(f"생성 완료: profinet_dcp.jsonl (team={team}, attacker_mac={attacker_mac(team)})")


if __name__ == "__main__":
    main()
