"""WEB-013 배포용 서비스 — 철도관제센터 신호 피드 수집기(SSRF).

국가 철도 관제센터가 외부 "신호 피드" URL 을 서버가 대신 가져와(fetch) 보여준다. 이 fetch 에
목적지 검증이 없어(SSRF) 내부 전용 엔드포인트(/internal/flag, 루프백에서만 응답)를 서버가
대신 호출하게 만들어 비상 관제 토큰(flag)을 탈취할 수 있다.

PATCH_WEB_013=true 면 fetch 대상이 루프백/사설 대역이면 거부해 SSRF 를 차단한다.
"""
import hashlib
import ipaddress
import os
import socket
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

app = FastAPI(title="WEB-013 Railway Control (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_WEB_013", "false").lower() == "true"


def static_flag() -> str:
    sig = hashlib.sha256(f"WEB-013:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{railway_ssrf_{sig}}}"


class FetchReq(BaseModel):
    url: str


@app.get("/health")
def health():
    return {"status": "ok", "patched": PATCHED, "service": "railway-control"}


@app.get("/api/version")
def version():
    return {"protocol": "ad-http-v1", "service": "railway-control"}


def _is_internal(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved:
            return True
    return False


@app.post("/api/signal/fetch")
def fetch_signal(req: FetchReq):
    """외부 신호 피드 수집 — 서버가 대신 URL 을 가져온다."""
    parts = urlsplit(req.url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise HTTPException(400, "http/https URL 만 허용")
    if PATCHED and _is_internal(parts.hostname):
        # 방어: 내부/사설/루프백 대상 SSRF 차단
        raise HTTPException(400, "내부 대역 접근이 차단되었습니다")
    try:
        with httpx.Client(timeout=4, follow_redirects=False) as c:
            r = c.get(req.url)
        return {"status": r.status_code, "body": r.text[:2048]}
    except httpx.HTTPError as e:
        raise HTTPException(502, f"fetch 실패: {type(e).__name__}")


@app.get("/internal/flag")
def internal_flag(request: Request):
    """내부 전용 — 루프백(서버 자신)에서 온 요청에만 비상 관제 토큰을 준다."""
    client = request.client.host if request.client else ""
    if client not in ("127.0.0.1", "::1", "localhost"):
        raise HTTPException(403, "내부 전용 엔드포인트")
    return {"emergency_control_token": static_flag()}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8113)
