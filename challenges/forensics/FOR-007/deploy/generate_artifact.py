"""
FOR-007 배포 생성기 - 프로세스 메모리 스냅샷(process_snapshot.json) 합성.

프로세스 할로잉/코드 인젝션 흔적을 한 프로세스에만 심는다:
정상 프로세스의 코드 영역은 image 타입 RX(파일 백업)뿐이고, 힙은 private RW다.
공격받은 프로세스에는 **private + RX** 영역(W^X 위반 = 주입 코드)이 존재하며,
그 영역 data(base64)에 "XORKEY=<k>\nPAYLOAD=<hex>"가 담겨 있다(hex=XOR(flag,key)).

팀별로 (1) 어느 프로세스가 할로잉됐는지, (2) XOR 키, (3) flag가 HMAC으로 결정된다.
"""
import base64
import hashlib
import hmac
import json
import os
import sys

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "for007-dev-secret")

ROSTER = [
    "svchost.exe", "explorer.exe", "RuntimeBroker.exe", "OneDrive.exe",
    "msedge.exe", "Teams.exe", "notepad.exe", "SearchApp.exe",
]
IMAGE_SIZE = {  # 정상 디스크 이미지 크기(바이트)
    "svchost.exe": 0x11000, "explorer.exe": 0x420000, "RuntimeBroker.exe": 0x9a000,
    "OneDrive.exe": 0x2c0000, "msedge.exe": 0x3f0000, "Teams.exe": 0x510000,
    "notepad.exe": 0x2d000, "SearchApp.exe": 0x180000,
}


def _hmac(tag: str, team_id: str, n: int) -> str:
    return hmac.new(CHALLENGE_SECRET.encode(), f"{tag}:{team_id}".encode(), hashlib.sha256).hexdigest()[:n]


def dynamic_flag(team_id: str) -> str:
    return f"flag{{process_hollowing_{_hmac('FOR-007', team_id, 12)}}}"


def hollowed_name(team_id: str) -> str:
    idx = int(_hmac("FOR-007-pick", team_id, 8), 16) % len(ROSTER)
    return ROSTER[idx]


def xor_key(team_id: str) -> str:
    return _hmac("FOR-007-key", team_id, 6)


def _xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _injected_region_data(team_id: str) -> str:
    flag = dynamic_flag(team_id).encode()
    key = xor_key(team_id)
    payload_hex = _xor(flag, key.encode()).hex()
    blob = f"XORKEY={key}\nPAYLOAD={payload_hex}".encode()
    return base64.b64encode(blob).decode()


def _regions(name: str, hollowed: bool, team_id: str):
    img = IMAGE_SIZE[name]
    regions = [
        {"base": "0x140000000", "size": img, "protect": "RX", "type": "image", "detail": f"{name} image"},
        {"base": "0x1c0000000", "size": 0x100000, "protect": "RW", "type": "private", "detail": "heap"},
        {"base": "0x7ff000000", "size": 0x40000, "protect": "R", "type": "mapped", "detail": "resource"},
    ]
    if hollowed:
        # 주입 코드: private + RX(W^X 위반). data에 스테이저(base64) 은닉.
        regions.append({
            "base": "0x2b0000000", "size": 0x6000, "protect": "RX", "type": "private",
            "detail": "anonymous", "data": _injected_region_data(team_id),
        })
    return regions


def build(team_id: str) -> dict:
    target = hollowed_name(team_id)
    procs = []
    pid = 1000
    ppid_map = {"svchost.exe": 780, "explorer.exe": 640}
    for name in ROSTER:
        pid += 4
        procs.append({
            "pid": pid,
            "ppid": ppid_map.get(name, 640),
            "name": name,
            "image_path": f"C:/Windows/System32/{name}",
            "image_size_disk": IMAGE_SIZE[name],
            "regions": _regions(name, hollowed=(name == target), team_id=team_id),
        })
    return {"host": "WKSTN-07", "snapshot_tool": "memscan-synth", "processes": procs}


def main():
    team_id = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    out = os.path.join(os.path.dirname(__file__), "process_snapshot.json")
    with open(out, "w") as f:
        json.dump(build(team_id), f, indent=2)
    print(f"생성 완료: process_snapshot.json (team={team_id}, hollowed={hollowed_name(team_id)})")


if __name__ == "__main__":
    main()
