"""
ICS-001 배포 - OPC UA 익명 태그 열람 챌린지 서버.

OPC UA 서버를 흉내낸 HTTP 서비스. 취약점: 익명 세션(인증 없음)으로 모든 노드를 읽을 수 있다.
노드 브라우즈로 은닉된 진단 노드(팀별 난독화 NodeId)를 찾아 익명으로 읽으면 플래그가 나온다.

실장비 무관 시뮬레이션. 모든 값은 합성 더미다.
"""
import hmac
import hashlib
import os
from fastapi import FastAPI

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "ics001-dev-secret")

app = FastAPI(title="ICS-001 OPC UA Anonymous Read (TRAINING ONLY)")


def flag_node(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"ICS-001-node:{team_id}".encode(), hashlib.sha256).hexdigest()[:8]
    return f"ns=4;s=Diag.Maint_{sig}"


def dynamic_flag(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"ICS-001:{team_id}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"flag{{opcua_anon_read_{sig}}}"


def _static_nodes():
    return {
        "ns=2;s=Boiler.TempC": 210.5,
        "ns=2;s=Boiler.PressureBar": 12.3,
        "ns=3;s=Pump.Status": "RUNNING",
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/opcua/browse")
def browse(team_id: str = "default"):
    # 취약: 익명으로 전체 주소공간 브라우즈 가능(은닉 진단 노드까지 노출)
    nodes = list(_static_nodes().keys()) + [flag_node(team_id)]
    return {"session": "anonymous", "nodes": sorted(nodes)}


@app.get("/opcua/read")
def read(node: str, team_id: str = "default"):
    # 취약: 익명 세션으로 임의 노드 읽기(인증/권한 없음)
    if node == flag_node(team_id):
        return {"node": node, "value": dynamic_flag(team_id), "access": "anonymous"}
    static = _static_nodes()
    if node in static:
        return {"node": node, "value": static[node], "access": "anonymous"}
    return {"node": node, "value": None, "error": "unknown node"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8111)
