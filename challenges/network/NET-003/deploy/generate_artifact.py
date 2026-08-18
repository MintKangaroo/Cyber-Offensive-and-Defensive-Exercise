"""NET-003 아티팩트 생성기 - C2 비콘이 섞인 연결 로그(conn_log.jsonl).

내부 호스트 한 대가 C2(198.51.100.50)로 정확히 60초 간격으로 비콘을 보낸다. 각 비콘에는
팀별 동적 implant id가 base64('IMPL:'+id)로 실려 있다. 정상 연결들은 불규칙한 시각에
다양한 목적지로 발생한다(비콘의 규칙성과 대비).
"""
import base64
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
C2_IP = "198.51.100.50"
BEACON_INTERVAL = 60
BEACON_SRC = "10.0.7.15"


def dynamic_implant(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"NET-003:{team_id}".encode(), hashlib.sha256).hexdigest()[:10]
    return f"IMP-{sig}"


def build_log(team_id: str) -> list[dict]:
    impl_b64 = base64.b64encode(f"IMPL:{dynamic_implant(team_id)}".encode()).decode()
    t0 = 1_700_300_000
    rows = []
    # 규칙적 비콘 8회(정확히 60초 간격)
    for i in range(8):
        rows.append({
            "ts": t0 + i * BEACON_INTERVAL, "src_ip": BEACON_SRC, "dst_ip": C2_IP,
            "dst_port": 443, "bytes": 512, "note": impl_b64,
        })
    # 정상 연결(불규칙 시각, 다양한 목적지)
    normal = [
        (5, "93.184.216.34", 443), (17, "140.82.112.3", 443), (41, "1.1.1.1", 53),
        (88, "151.101.1.69", 443), (133, "13.107.42.14", 443), (210, "93.184.216.34", 80),
        (295, "8.8.8.8", 53), (360, "140.82.112.3", 443),
    ]
    for off, dst, port in normal:
        rows.append({"ts": t0 + off, "src_ip": "10.0.7.22", "dst_ip": dst,
                     "dst_port": port, "bytes": 1500, "note": ""})
    rows.sort(key=lambda r: r["ts"])
    return rows


def generate(path: str, team_id: str) -> None:
    with open(path, "w") as f:
        for r in build_log(team_id):
            f.write(json.dumps(r) + "\n")


if __name__ == "__main__":
    team_id = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    generate("conn_log.jsonl", team_id)
    print(f"생성 완료: conn_log.jsonl (team={team_id})")
