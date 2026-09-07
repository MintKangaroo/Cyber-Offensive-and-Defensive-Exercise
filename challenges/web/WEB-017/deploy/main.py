"""WEB-017 배포용 서비스 — 한국공항공사 안내방송 템플릿 미리보기(SSTI).

공항 운영관제의 안내방송 편집기가 사용자가 입력한 템플릿을 Jinja2 로 '그대로' 렌더링한다
(render 대상에 사용자 입력). 서버측 템플릿 인젝션(SSTI)으로 파이썬 객체 그래프를 타고
임의 코드를 실행해 서버의 비상 대응 토큰(/app/flag.txt)을 읽을 수 있다.

PATCH_WEB_017=true 면 사용자 입력을 템플릿으로 렌더하지 않고 '데이터'로만 치환(자동
이스케이프)해 SSTI 를 차단한다.
"""
import hashlib
import os

from fastapi import FastAPI, HTTPException
from jinja2 import Environment, BaseLoader, select_autoescape
from pydantic import BaseModel, Field

app = FastAPI(title="WEB-017 Airport Notice Templater (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_WEB_017", "false").lower() == "true"
FLAG_PATH = os.environ.get("FLAG_PATH", "/app/flag.txt")


def static_flag() -> str:
    sig = hashlib.sha256(f"WEB-017:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{airport_ssti_{sig}}}"


with open(FLAG_PATH, "w", encoding="utf-8") as fh:
    fh.write(static_flag() + "\n")

_env = Environment(loader=BaseLoader(), autoescape=select_autoescape())


class Notice(BaseModel):
    gate: str = Field(min_length=1, max_length=20)
    template: str = Field(min_length=1, max_length=1024)


@app.get("/health")
def health():
    return {"status": "ok", "patched": PATCHED, "service": "airport-notice"}


@app.get("/api/version")
def version():
    return {"protocol": "ad-http-v1", "service": "airport-notice"}


@app.post("/api/notice/preview")
def preview(req: Notice):
    """안내방송 문안 미리보기. 예: '{{ gate }}번 게이트 탑승 안내'."""
    if PATCHED:
        # 방어: 사용자 입력을 템플릿으로 렌더하지 않고 데이터로만 치환
        rendered = req.template.replace("{{ gate }}", req.gate).replace("{{gate}}", req.gate)
        return {"rendered": rendered, "safe": True}
    try:
        # 취약: 사용자 입력을 Jinja2 템플릿으로 그대로 렌더(SSTI)
        rendered = _env.from_string(req.template).render(gate=req.gate)
    except Exception as e:
        raise HTTPException(400, f"렌더 오류: {str(e)[:120]}")
    return {"rendered": rendered}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8117)
