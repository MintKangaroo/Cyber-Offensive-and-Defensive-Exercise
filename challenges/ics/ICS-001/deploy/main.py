"""
ICS-001 배포 — OPC UA 익명 태그 열람 (실 OPC UA/TCP)
=====================================================
목업 HTTP 가 아니라 **진짜 OPC UA 바이너리 프로토콜**(포트 4840)을 말하는 보일러 컨트롤러.
UaExpert 계열 클라이언트가 하는 흐름 그대로 — HEL→ACK→OpenSecureChannel→CreateSession→
ActivateSession(Anonymous)→Browse→Read — 를 실제로 처리한다. 프로토콜 코어는 플랫폼 트윈과
동일한 `shared/ics/opcua.py` 를 재사용한다.

실전형 취약점: **익명 세션 허용 + 노드 접근 권한 부재.** 인증 없이 ActivateSession 이 통과하고,
주소공간 전체가 Browse 로 열거되며(은닉 진단 노드 포함), 임의 노드를 Read 할 수 있다. 은닉
진단 노드(ns=4;s=Diag.Maint_*)의 값이 팀 플래그다 — 전부 실 OPC UA 위에서 회수된다.

한 인스턴스는 TEAM_ID(기본 default)에 귀속된다. 팀별 동적 HMAC 으로 NodeId·플래그가 유니크.
모든 값은 합성 더미(실장비 무관).
"""
import asyncio
import hashlib
import hmac
import os

from shared.ics.opcua import serve, OPCUA_DEFAULT_PORT

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요.")

TEAM_ID = os.environ.get("TEAM_ID", "default")
PORT = int(os.environ.get("OPCUA_PORT", str(OPCUA_DEFAULT_PORT)))  # 4840, 비특권


def flag_node(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"ICS-001-node:{team_id}".encode(),
                   hashlib.sha256).hexdigest()[:8]
    return f"ns=4;s=Diag.Maint_{sig}"


def dynamic_flag(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"ICS-001:{team_id}".encode(),
                   hashlib.sha256).hexdigest()[:12]
    return f"flag{{opcua_anon_read_{sig}}}"


# 주소공간(정상 프로세스 태그 + 은닉 진단 노드)
_HIDDEN = flag_node(TEAM_ID)
ADDRESS_SPACE = {
    "ns=2;s=Boiler.TempC": 210.5,
    "ns=2;s=Boiler.PressureBar": 12.3,
    "ns=3;s=Pump.Status": 1,
    _HIDDEN: dynamic_flag(TEAM_ID),
}


def browse_nodes():
    """익명 Browse 로 노출되는 주소공간(취약: 진단 노드까지 열거됨)."""
    return [(n, n.split(";")[-1]) for n in ADDRESS_SPACE]


def read_node(node: str):
    """익명 Read(취약: 권한 검사 없음). 은닉 진단 노드 값 = 팀 플래그."""
    return ADDRESS_SPACE.get(node)


def on_read(node: str, peer):
    # 실 트윈이라면 여기서 SIEM access 로그(raw.protocol=opcua)를 발행한다.
    if node == _HIDDEN:
        print(f"[SIEM] anonymous read of diagnostic node {node} from {peer}", flush=True)


async def main():
    server = await serve(host="0.0.0.0", port=PORT,
                         browse_nodes=browse_nodes, read_node=read_node, on_read=on_read)
    print(f"ICS-001 OPC UA (TRAINING ONLY) listening on :{PORT} team={TEAM_ID}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
