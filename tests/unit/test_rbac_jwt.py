"""
RBAC 역할×엔드포인트 매트릭스 (P0-2) — JWT 인증 + 역할 게이트를 고정.
README의 RBAC 표를 테스트로 못박는다: 무토큰/타역할 → 401/403, 허용역할 → 통과.
"""
import time

import jwt
import pytest

import shared.rbac as rbac

SECRET = "matrix-test-secret"


def _tok(role: str, typ: str = "access") -> str:
    return jwt.encode({"sub": f"{role}1", "role": role, "type": typ,
                       "jti": f"j-{role}", "exp": int(time.time()) + 300}, SECRET, algorithm="HS256")


@pytest.fixture(autouse=True)
def _jwt_env(monkeypatch):
    # JWT 시크릿 설정 → dev 모드 해제, JWT 검증 활성. 정적 토큰은 없음.
    monkeypatch.setenv("AUTH_JWT_SECRET", SECRET)
    for r in ("INSTRUCTOR", "RED", "BLUE", "OBSERVER"):
        monkeypatch.delenv(f"{r}_TOKEN", raising=False)
    monkeypatch.delenv("RBAC_TOKENS", raising=False)


# (엔드포인트 라벨, 허용역할 집합) — README RBAC 표
ENDPOINTS = {
    "config /instructor/patch/toggle": {"instructor"},
    "instructor_api /scenario/start": {"instructor"},
    "edr /isolate·/kill (방어)": {"instructor", "blue"},
    "scoring /score/adjust": {"instructor"},
    "range /matches·/safety·/admin": {"instructor"},
}
ALL_ROLES = ["instructor", "red", "blue", "observer"]


@pytest.mark.parametrize("endpoint,allowed", list(ENDPOINTS.items()))
@pytest.mark.parametrize("role", ALL_ROLES)
def test_role_endpoint_matrix(endpoint, allowed, role):
    from fastapi import HTTPException
    auth = f"Bearer {_tok(role)}"
    if role in allowed:
        ident = rbac.require_role(auth, allowed)   # 통과해야 함
        assert ident.role == role
    else:
        with pytest.raises(HTTPException) as ei:   # 403 이어야 함
            rbac.require_role(auth, allowed)
        assert ei.value.status_code == 403


def test_no_token_401():
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as ei:
        rbac.require_role("", {"instructor"})
    assert ei.value.status_code == 401


def test_forged_signature_401():
    from fastapi import HTTPException
    bad = jwt.encode({"role": "instructor", "type": "access", "exp": int(time.time()) + 300},
                     "WRONG-SECRET", algorithm="HS256")
    with pytest.raises(HTTPException) as ei:
        rbac.require_role(f"Bearer {bad}", {"instructor"})
    assert ei.value.status_code == 401


def test_refresh_token_not_accepted_as_access():
    # refresh 타입 토큰으로는 인증 불가(access 전용)
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as ei:
        rbac.require_role(f"Bearer {_tok('instructor', 'refresh')}", {"instructor"})
    assert ei.value.status_code == 401


def test_static_token_backward_compat(monkeypatch):
    # JWT 시크릿 없이 정적 토큰만 있어도 기존 방식 동작(하위호환)
    monkeypatch.delenv("AUTH_JWT_SECRET", raising=False)
    monkeypatch.setenv("BLUE_TOKEN", "blue-static-xyz")
    ident = rbac.require_role("Bearer blue-static-xyz", {"blue", "instructor"})
    assert ident.role == "blue"


def test_dev_mode_when_nothing_configured(monkeypatch):
    # JWT 시크릿·정적 토큰 모두 없음 → dev 모드(무인증 instructor 통과)
    monkeypatch.delenv("AUTH_JWT_SECRET", raising=False)
    ident = rbac.require_role("", {"instructor"})
    assert ident.dev_mode is True and ident.role == "instructor"
