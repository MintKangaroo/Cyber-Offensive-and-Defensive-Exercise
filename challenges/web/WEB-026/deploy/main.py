"""WEB-026 배포용 서비스 — 스마트팜/농식품 관제 설정 임포트(YAML 역직렬화 RCE).

관제 설정을 YAML 로 임포트하는데 PyYAML 의 안전하지 않은 로더를 써서, !!python/object/apply
같은 태그로 임의 파이썬 호출이 발생한다(역직렬화 RCE). 이를 이용해 /app/flag.txt 를 읽는다.
WEB-005(pickle RCE)와 달리 YAML 역직렬화 유형이다. PATCH_WEB_026=true 면 yaml.safe_load 로 차단.
"""
import hashlib
import os

import yaml
from fastapi import FastAPI, HTTPException, Request

app = FastAPI(title="WEB-026 SmartFarm Config Import (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_WEB_026", "false").lower() == "true"
FLAG_PATH = os.environ.get("FLAG_PATH", "/app/flag.txt")


def static_flag() -> str:
    sig = hashlib.sha256(f"WEB-026:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{smartfarm_yaml_deser_{sig}}}"


with open(FLAG_PATH, "w", encoding="utf-8") as fh:
    fh.write(static_flag() + "\n")


@app.get("/health")
def health():
    return {"status": "ok", "patched": PATCHED, "service": "smartfarm-config"}


@app.get("/api/version")
def version():
    return {"protocol": "ad-http-v1", "service": "smartfarm-config"}


@app.post("/api/config/import")
async def import_config(request: Request):
    """관제 설정(YAML)을 임포트해 파싱 결과 요약을 돌려준다."""
    body = (await request.body()).decode("utf-8", "replace")
    if not body.strip():
        raise HTTPException(400, "빈 본문")
    try:
        if PATCHED:
            data = yaml.safe_load(body)          # 방어: 안전 로더(태그 실행 없음)
        else:
            data = yaml.load(body, Loader=yaml.UnsafeLoader)  # 취약: 임의 객체/호출
    except yaml.YAMLError as e:
        raise HTTPException(400, f"YAML 파싱 오류: {str(e)[:120]}")
    return {"loaded": str(data)[:1024]}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8132)
