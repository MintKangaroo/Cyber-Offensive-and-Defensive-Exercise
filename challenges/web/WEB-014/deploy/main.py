"""WEB-014 배포용 서비스 — K-water 수자원 관제 리포트 수집기(XXE).

상수도/수자원 관제센터가 현장 계측 리포트를 XML 로 업로드받아 파싱한다. XML 파서가 외부
엔티티(external entity)를 해석하도록 설정돼 있어(XXE), DTD 에 SYSTEM 엔티티를 심어 서버
로컬 파일(비상 대응 토큰)을 읽어낼 수 있다.

PATCH_WEB_014=true 면 엔티티 해석/DTD 로드를 끄고 네트워크 접근을 막아 XXE 를 차단한다.
"""
import hashlib
import os

from fastapi import FastAPI, HTTPException, Request
from lxml import etree

app = FastAPI(title="WEB-014 K-water Report Intake (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_WEB_014", "false").lower() == "true"
FLAG_PATH = os.environ.get("FLAG_PATH", "/app/flag.txt")


def static_flag() -> str:
    sig = hashlib.sha256(f"WEB-014:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{kwater_xxe_{sig}}}"


with open(FLAG_PATH, "w", encoding="utf-8") as fh:
    fh.write(static_flag() + "\n")


@app.get("/health")
def health():
    return {"status": "ok", "patched": PATCHED, "service": "kwater-report-intake"}


@app.get("/api/version")
def version():
    return {"protocol": "ad-http-v1", "service": "kwater-report-intake"}


@app.post("/api/report/import")
async def import_report(request: Request):
    """현장 계측 리포트(XML)를 업로드받아 title/site 를 파싱해 확인 응답.

    기대 형식: <report><site>..</site><title>..</title><level>..</level></report>
    """
    body = await request.body()
    if not body:
        raise HTTPException(400, "빈 본문")
    if PATCHED:
        # 방어: 엔티티 해석·DTD·네트워크 전면 차단
        parser = etree.XMLParser(
            resolve_entities=False, load_dtd=False, no_network=True, dtd_validation=False
        )
    else:
        # 취약: 외부 엔티티 해석 허용(XXE)
        parser = etree.XMLParser(
            resolve_entities=True, load_dtd=True, no_network=True
        )
    try:
        root = etree.fromstring(body, parser)
    except etree.XMLSyntaxError as e:
        raise HTTPException(400, f"XML 파싱 오류: {str(e)[:120]}")
    return {
        "accepted": True,
        "site": (root.findtext("site") or "").strip(),
        "title": (root.findtext("title") or "").strip(),
        "level": (root.findtext("level") or "").strip(),
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8114)
