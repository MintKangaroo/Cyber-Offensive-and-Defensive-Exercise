"""
WEB-007 배포용 취약 서비스 (독립 실행형 — 트윈에 없는 새 취약점 유형)
================================================================================
11번 문서 출제표준대로 독립 배포 가능한 스탠드얼론 앱. 파일 업로드 확장자 검증 우회.
취약점: 서버가 파일의 실제 확장자가 아니라 클라이언트가 보낸 content_type만 신뢰한다.
스크립트 확장자(.py 등)는 서버측에서 처리(시뮬레이션 실행)되어 승인 코드를 노출한다.
"""
import os
import hmac
import hashlib
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel

app = FastAPI(title="WEB-007 Challenge Deploy (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요.")
PATCHED = os.environ.get("PATCH_WEB_007", "false").lower() == "true"

IMAGE_TYPES = {"image/png", "image/jpeg", "image/gif"}
IMAGE_EXTS = {"png", "jpg", "jpeg", "gif"}
SCRIPT_EXTS = {"py", "pht", "phtml", "cgi", "sh"}  # 서버측 처리(시뮬레이션 실행) 대상


class UploadReq(BaseModel):
    filename: str
    content_type: str
    content: str = ""


def dynamic_flag(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"WEB-007:{team_id}".encode(), hashlib.sha256).hexdigest()[:16]
    return f"flag{{upload_bypass_{sig}}}"


def _ext(filename: str) -> str:
    return filename.rsplit(".", 1)[-1].lower() if "." in filename else ""


@app.get("/health")
def health():
    return {"status": "ok", "patched": PATCHED}


@app.post("/api/upload")
def upload(req: UploadReq, x_team_id: str = Header(default="default")):
    ext = _ext(req.filename)

    if PATCHED:
        # 패치판: 실제 확장자 화이트리스트로 검증(content_type은 신뢰하지 않음).
        if ext not in IMAGE_EXTS:
            raise HTTPException(400, f"rejected: extension '.{ext}' not in image allowlist")
    else:
        # 취약판: 클라이언트가 보낸 content_type만 검사 -> 위조 가능.
        if req.content_type not in IMAGE_TYPES:
            raise HTTPException(400, f"rejected: content_type '{req.content_type}' not an image")

    # 저장 후 처리: 스크립트 확장자면 서버측에서 처리(시뮬레이션 실행) -> 승인 코드 노출.
    if ext in SCRIPT_EXTS:
        return {
            "status": "processed",
            "stored_as": req.filename,
            "note": "server-side script executed",
            "approval_code": dynamic_flag(x_team_id),
        }
    return {"status": "stored", "stored_as": req.filename}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8100)
