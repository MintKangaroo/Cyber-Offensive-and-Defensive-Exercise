"""NET-004 아티팩트 생성기 - ARP 스푸핑 흔적이 담긴 ARP 로그(arp_log.jsonl).

정상 호스트들은 각자 하나의 (mac, ip)만 announce 한다. 공격자(팀별 동적 MAC)는 처음엔
자기 IP를 announce 하다가, 게이트웨이 IP(10.0.0.1)를 자기 MAC으로 announce 해 ARP
캐시를 오염(MITM)시킨다 → 게이트웨이 IP가 2개 MAC에서 관측된다.
"""
import hashlib
import hmac
import json
import os
import sys

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "net004-dev-secret")
GATEWAY_IP = "10.0.0.1"
GATEWAY_MAC = "aa:bb:cc:00:00:01"
ATTACKER_IP = "10.0.0.66"


def dynamic_mac(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"NET-004:{team_id}".encode(), hashlib.sha256).hexdigest()[:12]
    return ":".join(sig[i:i + 2] for i in range(0, 12, 2))


def build_log(team_id: str) -> list[dict]:
    atk_mac = dynamic_mac(team_id)
    t0 = 1_700_400_000
    rows = [
        {"ts": t0 + 0, "op": "reply", "sender_mac": GATEWAY_MAC, "sender_ip": GATEWAY_IP},
        {"ts": t0 + 5, "op": "reply", "sender_mac": "aa:bb:cc:00:00:11", "sender_ip": "10.0.0.11"},
        {"ts": t0 + 8, "op": "reply", "sender_mac": atk_mac, "sender_ip": ATTACKER_IP},      # 공격자 진짜 IP
        {"ts": t0 + 12, "op": "reply", "sender_mac": "aa:bb:cc:00:00:12", "sender_ip": "10.0.0.12"},
        {"ts": t0 + 20, "op": "reply", "sender_mac": atk_mac, "sender_ip": GATEWAY_IP},       # 게이트웨이 사칭(오염)
        {"ts": t0 + 25, "op": "reply", "sender_mac": GATEWAY_MAC, "sender_ip": GATEWAY_IP},
        {"ts": t0 + 30, "op": "reply", "sender_mac": "aa:bb:cc:00:00:13", "sender_ip": "10.0.0.13"},
    ]
    return rows


def generate(path: str, team_id: str) -> None:
    with open(path, "w") as f:
        for r in build_log(team_id):
            f.write(json.dumps(r) + "\n")


if __name__ == "__main__":
    team_id = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    generate("arp_log.jsonl", team_id)
    print(f"생성 완료: arp_log.jsonl (team={team_id})")
