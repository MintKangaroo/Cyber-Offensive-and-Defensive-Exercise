"""
FOR-002 배포 - 공격 세션 캡처 로그(JSON lines) 생성.
시나리오: 공격자(10.13.37.66)가 포트스캔 -> /api/telemetry SQLi -> 응답에 base64 유출.
"""
import json
import base64
import hmac
import hashlib
import os
import time

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요.")
ATTACKER_IP = "10.13.37.66"


def dynamic_flag(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"FOR-002:{team_id}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"flag{{pcap_carved_{sig}}}"


def generate_capture(path: str, team_id: str) -> None:
    flag = dynamic_flag(team_id)
    t0 = time.time()
    packets = []

    # 1) 포트스캔 흔적
    for i, port in enumerate([21, 22, 80, 443, 3306, 8001]):
        packets.append({"ts": t0 + i, "src_ip": ATTACKER_IP, "dst_ip": "10.0.0.10",
                        "dst_port": port, "type": "syn_scan"})

    # 2) SQLi 요청(HTTP)
    packets.append({
        "ts": t0 + 10, "src_ip": ATTACKER_IP, "dst_ip": "10.0.0.10", "dst_port": 8001,
        "type": "http_request",
        "payload": "GET /api/telemetry?sensor_id=x' UNION SELECT id,username,password,1 FROM users -- HTTP/1.1",
    })

    # 3) 유출 응답(base64 인코딩된 플래그)
    leaked = base64.b64encode(flag.encode()).decode()
    packets.append({
        "ts": t0 + 11, "src_ip": "10.0.0.10", "dst_ip": ATTACKER_IP, "dst_port": 8001,
        "type": "http_response",
        "payload": f'HTTP/1.1 200 OK\\r\\nContent-Type: application/json\\r\\n\\r\\n{{"results":[{{"secret":"{leaked}"}}]}}',
    })

    with open(path, "w") as f:
        for p in packets:
            f.write(json.dumps(p) + "\n")


if __name__ == "__main__":
    import sys
    team_id = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    generate_capture("capture_log.jsonl", team_id)
    print(f"생성 완료: capture_log.jsonl (team={team_id})")
