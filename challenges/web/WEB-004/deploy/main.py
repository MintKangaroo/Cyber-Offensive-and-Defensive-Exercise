"""WEB-004 배포용 취약 서비스 - 파일 다운로드 엔드포인트의 경로 순회(Path Traversal).

/api/files/download?name= 를 공개 디렉토리에 그대로 이어붙여 열기 때문에 `../` 로 상위
디렉토리의 파일(플래그)을 읽을 수 있다. PATCH_WEB_004=true 면 경로를 정규화/검증해 차단한다.
플래그는 CHALLENGE_SECRET 기반 정적 값으로 공개 디렉토리 밖(/app/flag.txt)에 기록된다.
"""
import os
import hashlib
from pathlib import Path
from fastapi import FastAPI, HTTPException

app = FastAPI(title="WEB-004 Challenge Deploy (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "web004-dev-secret")
PATCHED = os.environ.get("PATCH_WEB_004", "false").lower() == "true"
PUBLIC_DIR = Path(os.environ.get("PUBLIC_DIR", "/app/public"))
FLAG_PATH = os.environ.get("FLAG_PATH", "/app/flag.txt")


def static_flag() -> str:
    sig = hashlib.sha256(f"WEB-004:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{path_traversal_{sig}}}"


Path(FLAG_PATH).write_text(static_flag() + "\n")
PUBLIC_DIR.mkdir(parents=True, exist_ok=True)
(PUBLIC_DIR / "welcome.txt").write_text("Welcome to the Ground Station file service.\n")
(PUBLIC_DIR / "manual.txt").write_text("Operations manual v3. See ops team for details.\n")


@app.get("/health")
def health():
    return {"status": "ok", "patched": PATCHED}


@app.get("/api/files/download")
def download(name: str):
    """공개 문서 다운로드."""
    if PATCHED:
        # 안전: 파일명만 취해 공개 디렉토리로 한정
        safe = os.path.basename(name)
        target = PUBLIC_DIR / safe
        if not target.is_file():
            raise HTTPException(404, "not found")
        return {"filename": safe, "content": target.read_text(errors="replace")}
    # 취약: 사용자 입력을 그대로 이어붙임 -> ../ 순회 가능
    target = PUBLIC_DIR / name
    try:
        return {"filename": name, "content": target.read_text(errors="replace")}
    except (FileNotFoundError, IsADirectoryError):
        raise HTTPException(404, "not found")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8104)
