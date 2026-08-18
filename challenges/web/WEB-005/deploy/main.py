"""
WEB-005 배포용 취약 서비스 (독립 실행형 — power_plant 트윈에 의존하지 않음)
================================================================================
11번 문서 출제표준대로 독립 배포 가능한 스탠드얼론 앱. PP-004 히스토리안 역직렬화를
웹 문제로 정식화한다. 취약점: 신뢰할 수 없는 입력을 pickle.loads로 역직렬화 -> RCE.
"""
import os
import base64
import pickle
import hashlib
from pathlib import Path
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel

app = FastAPI(title="WEB-005 Challenge Deploy (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요.")
PATCHED = os.environ.get("PATCH_WEB_005", "false").lower() == "true"
FLAG_PATH = os.environ.get("FLAG_PATH", "/tmp/flag.txt")


def static_flag() -> str:
    sig = hashlib.sha256(f"WEB-005:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{pickle_rce_{sig}}}"


# 부팅 시 플래그 파일을 서버에 심어둔다(RCE로 읽어야 함).
Path(FLAG_PATH).write_text(static_flag() + "\n")


class ImportReq(BaseModel):
    data: str  # base64 (취약판=pickle, 패치판=JSON)


@app.get("/health")
def health():
    return {"status": "ok", "patched": PATCHED}


@app.post("/api/historian/import")
def import_report(req: ImportReq, x_team_id: str = Header(default="default")):
    try:
        raw = base64.b64decode(req.data)
    except Exception:
        raise HTTPException(400, "invalid base64")

    if PATCHED:
        # 패치판: 안전한 JSON 역직렬화만 허용. pickle 페이로드는 파싱 실패 -> 400.
        import json
        try:
            obj = json.loads(raw.decode("utf-8"))
        except Exception:
            raise HTTPException(400, "invalid report format (expected JSON)")
        return {"imported": str(obj)[:500]}
    else:
        # 취약판: 신뢰할 수 없는 입력을 pickle.loads -> __reduce__ 트리거로 RCE.
        obj = pickle.loads(raw)
        return {"imported": str(obj)[:500]}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8100)
