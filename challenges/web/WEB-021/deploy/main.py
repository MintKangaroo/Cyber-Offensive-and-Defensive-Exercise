"""WEB-021 배포용 서비스 — 국가 재난문자(CBS) 포털 웹 캐시 포이즈닝.

상태 페이지 /status 응답이 '경로만'을 캐시 키로 캐시된다(공유 캐시 모사). 그런데 응답 본문에
언키드(unkeyed) 헤더 X-Forwarded-Host 를 자산 CDN 호스트로 그대로 반영한다. 공격자가 악성
X-Forwarded-Host 로 한 번 요청하면 그 응답이 캐시에 저장돼, 헤더 없는 일반 사용자에게도
오염된 본문이 제공된다(웹 캐시 포이즈닝). 관제 검증기가 캐시 오염을 감지하면 비상 토큰(flag).

PATCH_WEB_021=true 면 X-Forwarded-Host 를 캐시 키에 포함(또는 무시)해 포이즈닝을 차단한다.
"""
import hashlib
import os
import time

from fastapi import FastAPI, Header, Request
from fastapi.responses import PlainTextResponse

app = FastAPI(title="WEB-021 CBS Portal (TRAINING ONLY)")

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요."
    )
PATCHED = os.environ.get("PATCH_WEB_021", "false").lower() == "true"
LEGIT_HOST = "cdn.cbs.go.kr"

# 공유 캐시: key -> (body, stored_at)
_CACHE: dict[str, tuple[str, float]] = {}
_TTL = 10.0


def static_flag() -> str:
    sig = hashlib.sha256(f"WEB-021:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{cache_poison_{sig}}}"


def _cache_key(path: str, xfh: str) -> str:
    if PATCHED:
        # 방어: 언키드였던 헤더를 캐시 키에 포함(호스트별로 분리 캐시)
        return f"{path}|{xfh}"
    # 취약: 경로만 키(헤더는 응답에 반영되지만 키엔 미포함)
    return path


@app.get("/health")
def health():
    return {"status": "ok", "patched": PATCHED, "service": "cbs-portal"}


@app.get("/api/version")
def version():
    return {"protocol": "ad-http-v1", "service": "cbs-portal"}


@app.get("/status", response_class=PlainTextResponse)
def status(request: Request, x_forwarded_host: str = Header(default="")):
    xfh = x_forwarded_host or LEGIT_HOST
    key = _cache_key("/status", xfh)
    cached = _CACHE.get(key)
    if cached and time.time() - cached[1] < _TTL:
        return PlainTextResponse(cached[0], headers={"X-Cache": "HIT"})
    # 응답 본문에 (언키드) 호스트를 자산 로더로 반영
    body = (
        "CBS 재난문자 관제 상태: 정상\n"
        f'<script src="//{xfh}/assets/cbs.js"></script>\n'
        "구독자: 51,240,000"
    )
    _CACHE[key] = (body, time.time())
    return PlainTextResponse(body, headers={"X-Cache": "MISS"})


@app.get("/admin/verify")
def verify():
    """관제 검증기 — 현재 캐시된 /status 가 정상 호스트가 아니면(오염) 비상 토큰 발급."""
    cached = _CACHE.get("/status")
    if cached and f"//{LEGIT_HOST}/" not in cached[0]:
        # 캐시가 정상 호스트가 아닌 값으로 오염됨
        return {"poisoned": True, "emergency_token": static_flag()}
    return {"poisoned": False, "detail": "캐시가 정상이거나 비어 있음"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8121)
