"""WEB-001 배포용 취약 서비스 - 네트워크 진단 엔드포인트의 명령 주입(Command Injection).

/api/net/ping?host= 를 셸로 그대로 넘겨 실행하므로 `; cat ...` 주입이 가능하다.
PATCH_WEB_001=true 면 인자 검증 + 배열 실행으로 안전화된다. 플래그는 CHALLENGE_SECRET 기반
정적 값으로 /app/flag.txt 에 기록된다(파일 읽기로 획득).
"""
import os
import re
import hashlib
import subprocess
from pathlib import Path
from fastapi import FastAPI, HTTPException

app = FastAPI(title="WEB-001 Challenge Deploy (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요.")
PATCHED = os.environ.get("PATCH_WEB_001", "false").lower() == "true"
FLAG_PATH = os.environ.get("FLAG_PATH", "/app/flag.txt")


def static_flag() -> str:
    sig = hashlib.sha256(f"WEB-001:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{cmd_injection_{sig}}}"


Path(FLAG_PATH).write_text(static_flag() + "\n")


@app.get("/health")
def health():
    return {"status": "ok", "patched": PATCHED}


@app.get("/api/net/ping")
def ping(host: str):
    """호스트 도달성 진단."""
    if PATCHED:
        if not re.match(r"^[A-Za-z0-9.\-]+$", host):
            raise HTTPException(400, "invalid host")
        out = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=5).stdout
        return {"output": out}
    # 취약: 사용자 입력을 셸 문자열로 그대로 실행
    out = subprocess.getoutput(f"ping -c 1 {host} 2>&1")
    return {"output": out}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8103)
