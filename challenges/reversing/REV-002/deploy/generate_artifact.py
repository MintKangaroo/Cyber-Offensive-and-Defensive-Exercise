"""REV-002 배포 - 팀별 플래그를 4바이트 반복키 XOR로 인코딩한 encoded.bin 생성.

REV-000(단일바이트 XOR)의 상위판: 키가 4바이트라 단일바이트 브루트포스로는 안 풀리고,
known-plaintext('flag{')로 반복키를 복원해야 한다.
"""
import hashlib
import hmac
import os

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요.")
XOR_KEY = bytes([0x13, 0x37, 0xAB, 0x5C])   # 4바이트 반복키


def dynamic_flag(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"REV-002:{team_id}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"flag{{rvx_{sig}}}"


def _xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def generate_encoded(path: str, team_id: str) -> None:
    flag = dynamic_flag(team_id)
    with open(path, "wb") as f:
        f.write(_xor(flag.encode(), XOR_KEY))


if __name__ == "__main__":
    import sys
    team_id = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    generate_encoded("encoded.bin", team_id)
    print(f"생성 완료: encoded.bin (team={team_id})")
