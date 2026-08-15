"""REV-005 배포 - 팀별 플래그를 LCG 키스트림으로 XOR한 cipher.bin 생성.

키스트림은 선형 합동 생성기(LCG, glibc 계열 파라미터)로 만든다. seed는 파일 앞 4바이트
(리틀엔디언)에 들어 있고, a/c/m 파라미터는 고정 상수다. 복호화하려면 LCG를 알아보고
seed로 키스트림을 재현해 XOR해야 한다.
"""
import hashlib
import hmac
import os
import struct
import sys

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요.")
A, C, M = 1103515245, 12345, 2 ** 31
SEED = 0x2468ACE


def dynamic_flag(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"REV-005:{team_id}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"flag{{lcg_{sig}}}"


def lcg_stream(seed: int, n: int) -> bytes:
    state = seed
    out = bytearray()
    for _ in range(n):
        state = (A * state + C) % M
        out.append((state >> 16) & 0xFF)
    return bytes(out)


def generate(path: str, team_id: str) -> None:
    flag = dynamic_flag(team_id).encode()
    ks = lcg_stream(SEED, len(flag))
    cipher = bytes(a ^ b for a, b in zip(flag, ks))
    with open(path, "wb") as f:
        f.write(struct.pack("<I", SEED) + cipher)   # 앞 4바이트 = seed


if __name__ == "__main__":
    team_id = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    generate("cipher.bin", team_id)
    print(f"생성 완료: cipher.bin (team={team_id})")
