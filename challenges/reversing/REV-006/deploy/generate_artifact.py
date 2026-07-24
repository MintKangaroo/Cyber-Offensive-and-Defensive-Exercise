"""REV-006 배포 - 팀별 플래그를 (XOR K 후 비트 ROL R)로 인코딩한 encoded.bin 생성.

각 바이트: enc = ROL((b XOR K), R). K/R은 고정이지만 아티팩트에 노출되지 않는다.
복호화는 known-plaintext('flag{')로 R(0~7)과 K를 복원해야 한다.
"""
import hashlib
import hmac
import os

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "rev006-dev-secret")
K = 0x6B
R = 3


def dynamic_flag(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"REV-006:{team_id}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"flag{{rol_{sig}}}"


def _rol(b: int, r: int) -> int:
    r &= 7
    return ((b << r) | (b >> (8 - r))) & 0xFF


def generate(path: str, team_id: str) -> None:
    flag = dynamic_flag(team_id).encode()
    enc = bytes(_rol(b ^ K, R) for b in flag)
    with open(path, "wb") as f:
        f.write(enc)


if __name__ == "__main__":
    import sys
    team_id = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    generate("encoded.bin", team_id)
    print(f"생성 완료: encoded.bin (team={team_id})")
