"""FOR-009 배포 - 팀별 안티포렌식 3단계 증거를 합성 disk_image.json 으로 생성.

단계 요약:
  1) 타임스톰프: 정상 파일은 journal_write <= mft_modified. 백데이팅된 단 하나의 파일만
     journal_write > mft_modified (MFT 시각을 과거로 되돌린 모순)을 갖는다.
  2) 은닉채널: 그 파일 slack = base64("channel:{CHID}\npayload:{hex}"). CHID는 팀별 HMAC.
  3) 복호: payload = flag 를 CHID 키로 반복 XOR 한 바이트열의 hex. 되돌리면 flag{...}.

모든 값이 팀별 HMAC(CHALLENGE_SECRET, "FOR-009...:team")로 결정론적으로 파생된다.
"""
import base64
import hashlib
import hmac
import json
import os
import random
import sys

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "for009-dev-secret")

BASE_TS = 1_700_000_000  # 기준 epoch (2023-11-14 근처)

NORMAL_FILES = [
    "System32/config/SAM", "System32/drivers/etc/hosts", "Users/svc/ntuser.dat",
    "ProgramData/telemetry.db", "Windows/Temp/wct1A2.tmp", "inetpub/logs/u_ex.log",
    "Users/admin/Documents/report.docx", "Windows/Prefetch/CMD.EXE.pf",
    "System32/winevt/Logs/Security.evtx", "Users/svc/AppData/update.dll",
    "ProgramData/cache/idx.bin", "Windows/Tasks/maint.job",
]

TAMPERED_NAME = "Users/svc/AppData/Roaming/.sync/agent.cfg"


def dynamic_flag(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"FOR-009:{team_id}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"flag{{antiforensic_{sig}}}"


def channel_id(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"FOR-009-chan:{team_id}".encode(), hashlib.sha256).hexdigest()[:8]
    return f"ch_{sig}"


def _rng(team_id: str) -> random.Random:
    seed = int(hmac.new(CHALLENGE_SECRET.encode(), f"FOR-009-rng:{team_id}".encode(),
                        hashlib.sha256).hexdigest(), 16)
    return random.Random(seed)


def _xor_repeat(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def build_image(team_id: str) -> dict:
    rng = _rng(team_id)
    chid = channel_id(team_id)
    flag = dynamic_flag(team_id)

    # 은닉 페이로드: flag 를 CHID 키로 반복 XOR -> hex
    payload_hex = _xor_repeat(flag.encode(), chid.encode()).hex()
    hidden = f"channel:{chid}\npayload:{payload_hex}"
    slack_b64 = base64.b64encode(hidden.encode()).decode()

    files = []

    # 정상 파일: journal_write <= mft_modified (쓰기 시점이 MFT 수정 시점 이하)
    for name in NORMAL_FILES:
        mft = BASE_TS + rng.randint(0, 5_000_000)
        jw = mft - rng.randint(0, 120)          # 저널이 같거나 살짝 이전
        # slack 은 정상적으로 랜덤 base64 잡음(디코드해도 의미 없음)
        noise = base64.b64encode(bytes(rng.getrandbits(8) for _ in range(rng.randint(8, 24)))).decode()
        files.append({
            "name": name,
            "mft_modified": mft,
            "journal_write": jw,
            "size": rng.randint(512, 4_000_000),
            "slack": noise,
        })

    # 타임스톰프 파일: mft_modified 를 과거로 되돌림 -> journal_write > mft_modified 모순
    real_write = BASE_TS + rng.randint(3_000_000, 5_000_000)
    backdated_mft = BASE_TS - rng.randint(10_000_000, 30_000_000)  # 훨씬 과거
    files.append({
        "name": TAMPERED_NAME,
        "mft_modified": backdated_mft,
        "journal_write": real_write,
        "size": len(slack_b64) + rng.randint(64, 512),
        "slack": slack_b64,
    })

    rng.shuffle(files)
    return {
        "fs": "ntfs-synth-v1",
        "note": "MFT $STANDARD_INFORMATION mft_modified vs $LogFile journal_write",
        "files": files,
    }


def generate(path: str, team_id: str) -> None:
    with open(path, "w") as f:
        json.dump(build_image(team_id), f)


if __name__ == "__main__":
    team_id = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    generate("disk_image.json", team_id)
    print(f"생성 완료: disk_image.json (team={team_id})")
