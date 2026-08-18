"""
NET-000 배포 - 평문 텔넷 로그인 세션을 흉내낸 캡처 로그(JSON lines) 생성.
실제 pcap 대신 패킷 페이로드를 JSON으로 표현(스카피 등 별도 의존성 없이 이식성 확보).
"""
import json
import hmac
import hashlib
import os

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요.")


def dynamic_password(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"NET-000:{team_id}".encode(), hashlib.sha256).hexdigest()[:8]
    return f"pw_{sig}"


def generate_capture(path: str, team_id: str) -> None:
    password = dynamic_password(team_id)
    packets = [
        {"src": "10.50.0.7", "dst": "10.0.0.20", "proto": "telnet", "payload": "login: "},
        {"src": "10.0.0.20", "dst": "10.50.0.7", "proto": "telnet", "payload": "svc_operator"},
        {"src": "10.50.0.7", "dst": "10.0.0.20", "proto": "telnet", "payload": "Password: "},
        {"src": "10.0.0.20", "dst": "10.50.0.7", "proto": "telnet", "payload": password},
        {"src": "10.50.0.7", "dst": "10.0.0.20", "proto": "telnet", "payload": "Login successful"},
    ]
    with open(path, "w") as f:
        for p in packets:
            f.write(json.dumps(p) + "\n")


if __name__ == "__main__":
    import sys
    team_id = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    generate_capture("capture_log.jsonl", team_id)
    print(f"생성 완료: capture_log.jsonl (team={team_id})")
