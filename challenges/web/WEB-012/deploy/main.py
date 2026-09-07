"""WEB-012 배포용 서비스 — 시흥무역항 화물 통제 시스템(클라이언트 로직 자동화).

실제 2025 사이버공격방어대회 본선 "시흥무역항"(클라이언트 JS 다단계 로직 퍼즐을 콘솔에서
자동 클리어)을 재구성. 화물 통관 게이트가 3개 스테이지를 순서대로 통과해야 열리고, 각
스테이지는 서버가 낸 파라미터에 대해 정해진 계산 결과를 제출해야 한다. 계산 규칙은 클라이언트
페이지(GET /)에 그대로 노출돼 있어 이를 읽고 자동화해야 한다. 게다가 START 후 STAGE_TIMEOUT
초 안에 3스테이지를 모두 통과해야 하므로 손이 아니라 스크립트로 풀어야 한다.

- stage 1: 하노이탑 최소 이동수 = 2^disks - 1
- stage 2: 부호 교대 합 = sum((-1)^i * a[i])  (배열 a 제공)
- stage 3: 롤링 체크섬 = (sum(i * v[i]) mod modulus)  (배열 v, modulus 제공)

3스테이지 통과 시 flag 반환. 규칙은 공개(클라이언트 로직) — 난이도는 "빠른 자동화".
"""
import hashlib
import os
import secrets
import time

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(title="WEB-012 Siheung Trade Port (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
STAGE_TIMEOUT = float(os.environ.get("STAGE_TIMEOUT", "10"))
_MOD = 100003


def static_flag() -> str:
    sig = hashlib.sha256(f"WEB-012:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{trade_port_logic_{sig}}}"


# session -> {"stage": int, "started": float, "params": dict}
_SESS: dict[str, dict] = {}


def _rng(session: str, stage: int) -> "secrets.SystemRandom":
    # 세션·스테이지 결정론 시드(제출 검증과 동일 파라미터 재현)
    seed = int(hashlib.sha256(f"{session}:{stage}:{CHALLENGE_SECRET}".encode()).hexdigest(), 16)
    import random
    return random.Random(seed)


def _params(session: str, stage: int) -> dict:
    r = _rng(session, stage)
    if stage == 1:
        return {"type": "hanoi_min_moves", "disks": r.randint(10, 40)}
    if stage == 2:
        return {"type": "alternating_sum", "array": [r.randint(1, 999) for _ in range(r.randint(8, 16))]}
    if stage == 3:
        return {"type": "rolling_checksum",
                "array": [r.randint(1, 9999) for _ in range(r.randint(8, 16))], "modulus": _MOD}
    raise HTTPException(400, "no such stage")


def _expected(stage: int, params: dict) -> int:
    if stage == 1:
        return (1 << params["disks"]) - 1
    if stage == 2:
        return sum(((-1) ** i) * v for i, v in enumerate(params["array"]))
    if stage == 3:
        return sum(i * v for i, v in enumerate(params["array"])) % params["modulus"]
    raise HTTPException(400, "no such stage")


class StartResp(BaseModel):
    session: str
    stage: int
    challenge: dict


class SubmitReq(BaseModel):
    session: str
    answer: int


@app.get("/health")
def health():
    return {"status": "ok", "service": "siheung-trade-port"}


@app.get("/api/version")
def version():
    return {"protocol": "ad-http-v1", "service": "siheung-trade-port"}


@app.get("/", response_class=HTMLResponse)
def index():
    return """<!doctype html><meta charset=utf-8><title>시흥무역항 화물 통제 시스템</title>
<h1>시흥무역항 화물 통제 게이트</h1>
<p>통관 게이트는 3단계 검증을 순서대로 통과해야 열립니다. 각 단계 규칙(클라이언트 로직):</p>
<pre>
POST /api/clearance/start                      -> { session, stage, challenge }
POST /api/clearance/submit { session, answer } -> 다음 challenge 또는 { flag }

stage 1 hanoi_min_moves : answer = 2**disks - 1
stage 2 alternating_sum : answer = sum( (-1)**i * array[i] )
stage 3 rolling_checksum: answer = ( sum( i * array[i] ) ) % modulus

주의: start 후 제한시간(기본 10초) 안에 3단계를 모두 통과해야 합니다. 손으로는 불가능하니
      규칙대로 자동화하세요.
</pre>"""


@app.post("/api/clearance/start", response_model=StartResp)
def start():
    session = secrets.token_urlsafe(12)
    _SESS[session] = {"stage": 1, "started": time.time()}
    return StartResp(session=session, stage=1, challenge=_params(session, 1))


@app.post("/api/clearance/submit")
def submit(req: SubmitReq):
    st = _SESS.get(req.session)
    if not st:
        raise HTTPException(404, "세션 없음 — /api/clearance/start 먼저")
    if time.time() - st["started"] > STAGE_TIMEOUT:
        _SESS.pop(req.session, None)
        raise HTTPException(408, "제한시간 초과 — 자동화가 필요합니다")
    stage = st["stage"]
    params = _params(req.session, stage)
    if req.answer != _expected(stage, params):
        _SESS.pop(req.session, None)
        raise HTTPException(400, f"stage {stage} 오답 — 세션 종료")
    if stage >= 3:
        _SESS.pop(req.session, None)
        return {"cleared": True, "flag": static_flag()}
    st["stage"] = stage + 1
    return {"cleared_stage": stage, "stage": stage + 1, "challenge": _params(req.session, stage + 1)}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8112)
