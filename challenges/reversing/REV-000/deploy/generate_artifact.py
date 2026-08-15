"""REV-000 배포 - 팀별 플래그를 단일바이트 XOR로 인코딩한 encoded.bin 생성."""
import hmac
import hashlib
import os

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요.")
XOR_KEY = 0x5A


def dynamic_flag(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"REV-000:{team_id}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"flag{{xor_{sig}}}"


def generate_encoded(path: str, team_id: str) -> None:
    flag = dynamic_flag(team_id)
    encoded = bytes(b ^ XOR_KEY for b in flag.encode())
    with open(path, "wb") as f:
        f.write(encoded)


if __name__ == "__main__":
    import sys
    team_id = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    generate_encoded("encoded.bin", team_id)
    print(f"생성 완료: encoded.bin (team={team_id})")
