"""NET-005 아티팩트 생성기 - 포트 노킹 흔적이 담긴 방화벽 로그(fw_log.jsonl).

공격자(한 IP)가 정해진 순서로 닫힌 포트 3개를 두드린(port knock) 뒤 보호된 포트(22)에
접속한다. 노킹 시퀀스는 팀별 동적. 정상 트래픽은 무작위 포트에 산발적으로 접속한다.
"""
import hashlib
import hmac
import json
import os
import sys

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요.")
ATTACKER_IP = "203.0.113.42"
PROTECTED_PORT = 22


def knock_sequence(team_id: str) -> list[int]:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"NET-005:{team_id}".encode(), hashlib.sha256).hexdigest()
    return [10000 + int(sig[i:i + 4], 16) % 50000 for i in range(0, 12, 4)]


def build_log(team_id: str) -> list[dict]:
    seq = knock_sequence(team_id)
    t0 = 1_700_500_000
    rows = []
    i = 0
    # 정상 잡음(무작위 포트, 여러 IP)
    for ip, port, off in [("10.0.2.5", 443, 0), ("10.0.2.6", 80, 3), ("10.0.2.7", 53, 6),
                          ("10.0.2.5", 8080, 40), ("10.0.2.8", 443, 55)]:
        rows.append({"ts": t0 + off, "src_ip": ip, "dst_port": port, "action": "allow"}); i += 1
    # 공격자: 노킹 시퀀스(닫힌 포트, drop) 후 보호 포트 접속(allow)
    kt = t0 + 100
    for k, port in enumerate(seq):
        rows.append({"ts": kt + k * 2, "src_ip": ATTACKER_IP, "dst_port": port, "action": "drop"})
    rows.append({"ts": kt + len(seq) * 2 + 1, "src_ip": ATTACKER_IP, "dst_port": PROTECTED_PORT, "action": "allow"})
    rows.sort(key=lambda r: r["ts"])
    return rows


def generate(path: str, team_id: str) -> None:
    with open(path, "w") as f:
        for r in build_log(team_id):
            f.write(json.dumps(r) + "\n")


if __name__ == "__main__":
    team_id = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    generate("fw_log.jsonl", team_id)
    print(f"생성 완료: fw_log.jsonl (team={team_id})")
