"""
서비스 간(S2S) 토큰 인증 (감사 3.1)
=====================================
event_collector `/events`, scoring_engine `/score/ingest` 같은 '내부 ingest' 엔드포인트를
보호한다. 이전엔 무인증이라 참가자망에서 도달만 하면 임의 이벤트/점수를 주입할 수 있었다
(채점 조작 갭). 네트워크 격리(감사 3.2)와 함께 심층방어를 이룬다.

정책(fail-safe 롤아웃):
  - SERVICE_TOKEN 설정됨(운영): `Authorization: Bearer <SERVICE_TOKEN>` 일치만 통과, 그 외 401.
  - SERVICE_TOKEN 미설정 + RBAC_ALLOW_INSECURE_DEV=true: dev 통과(로컬/CI 편의).
  - SERVICE_TOKEN 미설정 + opt-in 없음: fail-closed 401.
호출측은 service_headers()로 동일 env의 토큰을 실어 보낸다(한 곳에서 관리).
"""
from __future__ import annotations

import os


def _service_token() -> str:
    return os.environ.get("SERVICE_TOKEN", "").strip()


def _insecure_dev_allowed() -> bool:
    return os.environ.get("RBAC_ALLOW_INSECURE_DEV", "").strip().lower() in ("1", "true", "yes", "on")


def _bearer(authorization: str) -> str:
    return (authorization or "").replace("Bearer ", "").strip()


def service_headers() -> dict[str, str]:
    """내부 caller가 ingest 엔드포인트로 보낼 인증 헤더. SERVICE_TOKEN 미설정이면 빈 dict."""
    tok = _service_token()
    return {"Authorization": f"Bearer {tok}"} if tok else {}


def require_service_token(authorization: str) -> None:
    """ingest 엔드포인트 게이트. 실패 시 HTTPException(401). shared.rbac와 동일한 fail-closed."""
    from fastapi import HTTPException
    expected = _service_token()
    if expected:
        if _bearer(authorization) != expected:
            raise HTTPException(status_code=401, detail="invalid or missing service token")
        return
    # SERVICE_TOKEN 미설정: dev opt-in 있을 때만 통과.
    if _insecure_dev_allowed():
        return
    raise HTTPException(
        status_code=401,
        detail="ingest not configured (fail-closed): set SERVICE_TOKEN, "
               "or RBAC_ALLOW_INSECURE_DEV=true for local dev only",
    )
