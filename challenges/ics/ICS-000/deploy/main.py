"""
ICS-000 배포 - 안전 인터록 우회(Modbus) 챌린지 서버.

Modbus 홀딩 레지스터를 흉내낸 HTTP 서비스. 취약점:
  1) 정보 노출: GET /modbus/registers 가 SAFETY_KEY(안전 쓰기 인증 키)를 그대로 덤프한다.
  2) 안전 우회: 그 키로 SAFETY_INTERLOCK(40001)을 0으로 쓰면 인터록이 해제되고,
     서버가 사보타주 성공으로 판정해 팀별 플래그를 발급한다.

실제 장비와 무관한 시뮬레이션. 모든 값은 합성 더미다.
"""
import hmac
import hashlib
import os
from fastapi import FastAPI
from pydantic import BaseModel

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요.")

app = FastAPI(title="ICS-000 Modbus Safety Interlock (TRAINING ONLY)")

# 주소 레이아웃(홀딩 레지스터)
ADDR_INTERLOCK = 40001    # 1=engaged(안전), 0=bypassed
ADDR_TURBINE_RPM = 40002
ADDR_SAFETY_KEY = 40100   # ⚠ 정보노출: 안전 쓰기 인증 키가 읽기 가능


def safety_key(team_id: str) -> str:
    return "SK-" + hmac.new(CHALLENGE_SECRET.encode(), f"ICS-000-key:{team_id}".encode(), hashlib.sha256).hexdigest()[:8]


def dynamic_flag(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"ICS-000:{team_id}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"flag{{modbus_interlock_bypass_{sig}}}"


class WriteRequest(BaseModel):
    addr: int
    value: int
    key: str = ""
    team_id: str = "default"


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/modbus/registers")
def registers(team_id: str = "default"):
    # 취약: 안전 쓰기 인증 키를 레지스터 덤프로 노출
    return {
        "unit_id": 1,
        "holding_registers": {
            str(ADDR_INTERLOCK): 1,
            str(ADDR_TURBINE_RPM): 3000,
            str(ADDR_SAFETY_KEY): safety_key(team_id),
        },
        "note": "40100 = SAFETY_KEY (should not be readable in production)",
    }


@app.post("/modbus/write")
def write(req: WriteRequest):
    if req.addr != ADDR_INTERLOCK:
        return {"ok": True, "addr": req.addr, "value": req.value, "note": "written"}
    # 인터록 쓰기: 안전 키 필요(하지만 위에서 노출됨)
    if req.key != safety_key(req.team_id):
        return {"ok": False, "error": "invalid SAFETY_KEY for interlock write"}
    if req.value == 0:
        return {"ok": True, "interlock": "BYPASSED",
                "alarm": "SAFETY INTERLOCK DISABLED", "flag": dynamic_flag(req.team_id)}
    return {"ok": True, "interlock": "engaged"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8110)
