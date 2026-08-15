"""
REV-001 배포 아티팩트 - 시리얼 검증기(소스 공개, 바이너리 디스어셈블 없이
'알고리즘을 읽고 이해해서 키젠을 만드는' 유형의 리버싱 문제).

검증 절차: raw16(팀별 유니크) -> Caesar shift(+5) -> 문자열 반전 -> 체크섬 문자 부착.
"""
import hashlib
import os

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요.")
ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"  # 36자


def derive_raw16(team_id: str) -> str:
    """팀별 유니크 원본 16자(0-9A-F 부분집합, ALPHABET의 서브셋)."""
    h = hashlib.sha256(f"{CHALLENGE_SECRET}:REV-001:{team_id}".encode()).hexdigest()
    return h[:16].upper()


def transform(raw16: str) -> str:
    shifted = "".join(ALPHABET[(ALPHABET.index(c) + 5) % 36] for c in raw16)
    reversed_s = shifted[::-1]
    checksum_val = 0
    for c in reversed_s:
        checksum_val ^= ord(c)
    checksum_char = ALPHABET[checksum_val % 36]
    return reversed_s + checksum_char  # 17자(16 + 체크섬 1)


def format_serial(raw17: str) -> str:
    """17자를 'XXXX-XXXX-XXXX-XXXX' + 여분 1자 형태가 아니라, 16자만 그룹핑하고
    체크섬은 마지막에 별도 구분자로 붙인다: XXXX-XXXX-XXXX-XXXX-C"""
    body = raw17[:16]
    checksum = raw17[16]
    groups = [body[i:i + 4] for i in range(0, 16, 4)]
    return "-".join(groups) + "-" + checksum


def expected_serial(team_id: str) -> str:
    return format_serial(transform(derive_raw16(team_id)))


def validate(serial_with_dashes: str, team_id: str) -> bool:
    return serial_with_dashes.strip().upper() == expected_serial(team_id)


if __name__ == "__main__":
    import sys
    team_id = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    serial = sys.argv[2] if len(sys.argv) > 2 else ""
    print("valid" if validate(serial, team_id) else "invalid")
