"""REV-003 배포 - 팀별 플래그를 3계층(XOR→역순→base64)으로 인코딩한 encoded.txt 생성.

계층 순서(인코딩): flag --XOR(1바이트)--> --바이트 역순--> --base64--> 텍스트.
복호화는 역순으로: base64 디코드 -> 역순 복원 -> known-plaintext로 XOR 키 복원 -> 디코드.
"""
import base64
import hashlib
import hmac
import os

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요.")
XOR_KEY = 0x2A


def dynamic_flag(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"REV-003:{team_id}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"flag{{ml_{sig}}}"


def encode(flag: str) -> str:
    xored = bytes(b ^ XOR_KEY for b in flag.encode())   # 계층1: XOR
    reversed_bytes = xored[::-1]                          # 계층2: 바이트 역순
    return base64.b64encode(reversed_bytes).decode()     # 계층3: base64


def generate(path: str, team_id: str) -> None:
    with open(path, "w") as f:
        f.write(encode(dynamic_flag(team_id)) + "\n")


if __name__ == "__main__":
    import sys
    team_id = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    generate("encoded.txt", team_id)
    print(f"생성 완료: encoded.txt (team={team_id})")
