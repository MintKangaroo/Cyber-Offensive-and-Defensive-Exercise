"""WEB-025 배포용 서비스 — 정부 G-Cloud 인스턴스 콘솔(SSRF → 클라우드 메타데이터 자격증명 탈취).

인스턴스 상태 수집기가 사용자 URL 을 목적지 검증 없이 서버가 대신 fetch 한다(SSRF). 클라우드
메타데이터 서비스(IMDS, 링크로컬 169.254.169.254 및 컨테이너 loopback 에서만 응답)를 서버가
대신 호출하게 만들어 IAM 임시 자격증명(SecretAccessKey=flag)을 탈취할 수 있다.

WEB-013(단순 내부 SSRF)과 달리 '클라우드 메타데이터/IAM 크리덴셜 도난' 시나리오다.
PATCH_WEB_025=true 면 목적지가 루프백/사설/링크로컬(169.254.0.0/16 포함)이면 차단한다.
"""
import hashlib
import ipaddress
import os
import socket
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

app = FastAPI(title="WEB-025 G-Cloud Console (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_WEB_025", "false").lower() == "true"
PORT = int(os.environ.get("PORT", "8131"))


def static_flag() -> str:
    sig = hashlib.sha256(f"WEB-025:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{gcloud_imds_ssrf_{sig}}}"


class FetchReq(BaseModel):
    url: str


def _is_blocked(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved:
            return True
    return False


@app.get("/health")
def health():
    return {"status": "ok", "patched": PATCHED, "service": "gcloud-console"}


@app.get("/api/version")
def version():
    return {"protocol": "ad-http-v1", "service": "gcloud-console"}


@app.post("/api/instance/collect")
def collect(req: FetchReq):
    """인스턴스 상태 피드 수집 — 서버가 대신 URL 을 가져온다(취약: SSRF)."""
    parts = urlsplit(req.url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise HTTPException(400, "http/https URL 만 허용")
    if PATCHED and _is_blocked(parts.hostname):
        raise HTTPException(400, "내부/메타데이터 대역 접근 차단")
    try:
        with httpx.Client(timeout=4, follow_redirects=False) as c:
            r = c.get(req.url, headers={"Metadata-Flavor": "Google"})
        return {"status": r.status_code, "body": r.text[:2048]}
    except httpx.HTTPError as e:
        raise HTTPException(502, f"수집 실패: {type(e).__name__}")


# ---- Mock IMDS(클라우드 메타데이터) — loopback 에서만 응답 ------------------
@app.get("/computeMetadata/v1/instance/service-accounts/default/token")
@app.get("/latest/meta-data/iam/security-credentials/gcloud-ops-role")
def imds_credentials(request: Request):
    client = request.client.host if request.client else ""
    if client not in ("127.0.0.1", "::1", "localhost"):
        raise HTTPException(403, "메타데이터는 인스턴스 내부에서만 접근 가능")
    return {
        "Code": "Success",
        "Type": "AWS-HMAC",
        "AccessKeyId": "ASIA" + "GCLOUDOPS0000",
        "SecretAccessKey": static_flag(),
        "Token": "IQoJb3JpZ2luX2VjE...",
    }


@app.get("/latest/meta-data/iam/security-credentials/")
def imds_list(request: Request):
    client = request.client.host if request.client else ""
    if client not in ("127.0.0.1", "::1", "localhost"):
        raise HTTPException(403, "메타데이터는 인스턴스 내부에서만 접근 가능")
    return "gcloud-ops-role"


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=PORT)
