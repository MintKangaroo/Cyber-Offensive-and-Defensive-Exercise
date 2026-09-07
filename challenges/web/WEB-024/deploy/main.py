"""WEB-024 배포용 서비스 — 상수도 요금 고지 시스템(2차 SQL 인젝션).

가입 시 저장된 username 이 그 시점엔 무해해 보이지만, 나중에 '요금 리포트 생성'이 그 저장값을
문자열 결합으로 SQL 에 다시 넣는다(second-order). 저장 username 에 UNION 페이로드를 넣으면
비밀 테이블(secrets)의 비상 정산 토큰(flag)을 조회할 수 있다.

PATCH_WEB_024=true 면 리포트 쿼리를 파라미터 바인딩으로 바꿔 2차 주입을 차단한다.
"""
import hashlib
import os
import sqlite3
import threading

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="WEB-024 Water Billing (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_WEB_024", "false").lower() == "true"


def static_flag() -> str:
    sig = hashlib.sha256(f"WEB-024:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{second_order_sqli_{sig}}}"


_db = sqlite3.connect(":memory:", check_same_thread=False)
_db.row_factory = sqlite3.Row
_lock = threading.Lock()
with _lock:
    _db.executescript(
        "CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, meter_no TEXT);"
        "CREATE TABLE secrets(name TEXT, value TEXT);"
    )
    _db.execute("INSERT INTO secrets(name,value) VALUES('emergency_settlement',?)", (static_flag(),))
    _db.commit()


class RegisterReq(BaseModel):
    username: str = Field(min_length=1, max_length=200)
    meter_no: str = Field(min_length=1, max_length=40)


class ReportReq(BaseModel):
    username: str = Field(min_length=1, max_length=200)


@app.get("/health")
def health():
    return {"status": "ok", "patched": PATCHED, "service": "water-billing"}


@app.get("/api/version")
def version():
    return {"protocol": "ad-http-v1", "service": "water-billing"}


@app.post("/api/register", status_code=201)
def register(req: RegisterReq):
    # 저장은 파라미터 바인딩(1차엔 무해) — username 원문 그대로 저장됨
    with _lock:
        _db.execute("INSERT INTO users(username,meter_no) VALUES(?,?)", (req.username, req.meter_no))
        _db.commit()
    return {"registered": True}


@app.post("/api/report/generate")
def generate(req: ReportReq):
    """요금 리포트 — 저장된 username 을 조회해 미터번호 목록을 반환."""
    with _lock:
        row = _db.execute(
            "SELECT username FROM users WHERE username=? LIMIT 1", (req.username,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "가입 정보 없음")
        stored = row["username"]              # 저장값(공격 페이로드일 수 있음)
        if PATCHED:
            # 방어: 파라미터 바인딩
            rows = _db.execute(
                "SELECT meter_no FROM users WHERE username=?", (stored,)
            ).fetchall()
        else:
            # 취약: 저장된 username 을 문자열 결합으로 재사용(2차 SQLi)
            q = "SELECT meter_no FROM users WHERE username='" + stored + "'"
            rows = _db.execute(q).fetchall()
    return {"report": [dict(r) for r in rows]}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8128)
