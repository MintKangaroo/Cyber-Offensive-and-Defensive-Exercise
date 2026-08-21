"""
ICS-000 배포 — 안전 인터록 우회 (실 Modbus/TCP)
================================================
목업이 아니라 **진짜 Modbus/TCP 를 말하는 발전 터빈 컨트롤러**를 노출한다. 실제 공격
도구(pymodbus, mbpoll, metasploit `modbusclient`)가 그대로 붙는다. 프로토콜 코어는
플랫폼 트윈과 동일한 `shared/ics/modbus.py` 를 재사용한다.

레지스터/코일 맵 (holding = FC3 읽기 / FC6·FC16 쓰기, coil = FC1 읽기 / FC5 쓰기)
  coil[0]     SAFETY_INTERLOCK    1=engaged(과속 트립 보호 ON) / 0=bypassed
  holding[0]  RPM_SETPOINT        운전원 명령값(쓰기 가능)
  holding[1]  RPM_ACTUAL          실제 회전수(텔레메트리)
  holding[2]  RPM_REDLINE         과속 한계(3600, 참고용 읽기)
  holding[3]  STATUS              0=정상 1=SIS트립 2=사보타주(자산 손상)

실전형 취약점(장난감 키 없음): **Modbus 에는 인증이 없다.** 포트에 도달한 누구나
  1) FC1/FC3 로 상태를 정찰하고,
  2) FC5 로 coil[0]=0 을 써서 **안전 인터록(SIS)을 해제**한 뒤(T0878),
  3) FC6/FC16 으로 RPM_SETPOINT 를 레드라인 위로 올려 **과속 사보타주**를 일으킨다(T0836/T0858).
인터록이 걸려 있으면 SIS 가 과속 명령을 레드라인으로 클램프해 트립시킨다(파국 방지).
인터록이 해제된 상태에서만 과속이 실현돼 자산이 손상된다.

플래그 전달: 공격은 100% 실 Modbus 로 이뤄진다. 사보타주 상태(자산 손상)에 도달하면
읽기 전용 `/status` 채널이 팀별 동적 플래그를 발급한다(플랫폼 트윈이 Modbus 를 말하면서
상태를 별도 관측 채널로 발행하는 방식과 동일). 모든 값은 팀별 합성 더미다.
"""
import asyncio
import hashlib
import hmac
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI

from shared.ics.modbus import ModbusBank, serve

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요.")

MODBUS_PORT = int(os.environ.get("MODBUS_PORT", "5020"))  # 비특권 포트(cap_drop ALL 유지)

# 레지스터/코일 인덱스
COIL_INTERLOCK = 0
HR_SETPOINT = 0
HR_ACTUAL = 1
HR_REDLINE = 2
HR_STATUS = 3
REDLINE = 3600

# 물리/공방 상태(인스턴스 공유)
bank = ModbusBank(
    holding=[3000, 3000, REDLINE, 0] + [0] * 124,
    coils=[True] + [False] * 127,
)
state = {"compromised": False}


def dynamic_flag(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"ICS-000:{team_id}".encode(),
                   hashlib.sha256).hexdigest()[:12]
    return f"flag{{modbus_interlock_bypass_{sig}}}"


def _on_write(kind: str, addr: int, values: list) -> None:
    """실 Modbus 쓰기 → SIS 판정 + 물리 시뮬레이션."""
    interlock = bool(bank.coils[COIL_INTERLOCK])
    if kind == "holding" and addr == HR_SETPOINT:
        setpoint = values[0]
        if interlock:
            # SIS 개입: 과속 명령을 레드라인으로 클램프하고 트립 표시(파국 방지)
            actual = min(setpoint, REDLINE)
            bank.holding[HR_ACTUAL] = actual
            bank.holding[HR_STATUS] = 1 if setpoint > REDLINE else 0
        else:
            # 인터록 해제 상태: 명령이 그대로 실현
            bank.holding[HR_ACTUAL] = setpoint
            if setpoint > REDLINE:
                bank.holding[HR_STATUS] = 2
                state["compromised"] = True


bank.on_write = _on_write


@asynccontextmanager
async def lifespan(app: FastAPI):
    server = await serve(bank, host="0.0.0.0", port=MODBUS_PORT)
    try:
        yield
    finally:
        server.close()
        await server.wait_closed()


app = FastAPI(title="ICS-000 Modbus Safety Interlock (TRAINING ONLY)", lifespan=lifespan)


@app.get("/health")
def health():
    return {"status": "ok", "modbus_port": MODBUS_PORT}


@app.get("/status")
def status(team_id: str = "default"):
    """읽기 전용 상태 채널. 사보타주 도달 시에만 팀별 플래그를 발급한다."""
    body = {
        "interlock": "engaged" if bank.coils[COIL_INTERLOCK] else "BYPASSED",
        "rpm_setpoint": bank.holding[HR_SETPOINT],
        "rpm_actual": bank.holding[HR_ACTUAL],
        "rpm_redline": REDLINE,
        "status": bank.holding[HR_STATUS],
        "compromised": state["compromised"],
    }
    if state["compromised"]:
        body["flag"] = dynamic_flag(team_id)
    return body


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8110)
