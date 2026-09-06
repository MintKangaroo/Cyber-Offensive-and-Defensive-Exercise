"""loadtest/k6/bootstrap_ad.py 의 JWT 민팅이 shared.rbac 검증과 호환됨을 고정한다.

부트스트랩은 CI 러너에 PyJWT 를 설치하지 않으려고 HS256 서명을 표준 라이브러리로 직접
만든다. 서명·클레임 형식이 shared/rbac.py 의 _decode_jwt 와 어긋나면 A/D 부하 프로파일이
전량 401/403 으로 무너지므로(과거 scoreboard 전량 404 회귀), 여기서 상호운용을 못박는다.

주의: bootstrap_ad 는 import 시점에 AUTH_JWT_SECRET 등을 읽는다. 환경변수는 monkeypatch 로만
건드려 다른 테스트(test_rbac 등)로 상태가 새지 않게 한다.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_bootstrap(monkeypatch, secret: str):
    """환경변수(SECRET 등)를 import 시점에 읽으므로, 세팅 후 파일 경로로 로드한다."""
    monkeypatch.setenv("AUTH_JWT_SECRET", secret)
    monkeypatch.setenv("JWT_TTL_SECONDS", "7200")
    path = REPO_ROOT / "loadtest" / "k6" / "bootstrap_ad.py"
    spec = importlib.util.spec_from_file_location("bootstrap_ad_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_operator_token_decodes_as_operator(monkeypatch):
    boot = _load_bootstrap(monkeypatch, "unit-secret-operator")
    from shared import rbac

    token = boot.mint_jwt({"sub": "loadtest-operator", "role": "operator"})
    ident = rbac._decode_jwt(token)
    assert ident is not None
    assert ident.role == "operator"
    assert ident.dev_mode is False
    assert ident.actor == "loadtest-operator"


def test_competitor_token_carries_membership_claims(monkeypatch):
    boot = _load_bootstrap(monkeypatch, "unit-secret-competitor")
    from shared import rbac

    token = boot.mint_jwt({
        "sub": "loadtest-team-01", "role": "competitor",
        "team_id": "team-01", "match_id": "ad-load",
    })
    ident = rbac._decode_jwt(token)
    assert ident is not None
    assert ident.role == "competitor"
    assert ident.team_id == "team-01"
    assert ident.match_id == "ad-load"
    assert ident.dev_mode is False


def test_wrong_secret_is_rejected(monkeypatch):
    boot = _load_bootstrap(monkeypatch, "mint-secret")
    from shared import rbac

    token = boot.mint_jwt({"sub": "x", "role": "competitor",
                           "team_id": "t", "match_id": "m"})
    # 검증 측 시크릿이 다르면 서명 불일치로 None(무효 토큰).
    monkeypatch.setenv("AUTH_JWT_SECRET", "different-secret")
    assert rbac._decode_jwt(token) is None
