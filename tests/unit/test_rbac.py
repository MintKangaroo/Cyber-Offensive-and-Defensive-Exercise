"""
공유 RBAC 유닛 테스트 (P3)
============================
토큰→역할 매핑, dev 모드 통과, 401(무효토큰)/403(역할부족) 경계를 검증.
"""
import pytest
from fastapi import HTTPException

from shared import rbac

TOKEN_ENVS = ["INSTRUCTOR_TOKEN", "RED_TOKEN", "BLUE_TOKEN", "OBSERVER_TOKEN", "RBAC_TOKENS",
              "OBSERVER_READ_ENFORCE", "RBAC_ALLOW_INSECURE_DEV"]


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    """각 테스트는 깨끗한 토큰 환경에서 시작(누수 방지)."""
    for k in TOKEN_ENVS:
        monkeypatch.delenv(k, raising=False)
    yield


def _bearer(tok):
    return f"Bearer {tok}"


# --- dev 모드(토큰 미설정) --------------------------------------------------

def test_authenticate_marks_dev_mode_when_unconfigured():
    # authenticate()는 dev_mode 후보로만 '표시'한다(통과 허용은 require_role이 결정).
    ident = rbac.authenticate("")
    assert ident.dev_mode is True
    assert ident.role == "instructor"


def test_dev_mode_fails_closed_without_explicit_optin():
    # DoD 1.6: 시크릿 미설정 + opt-in 없음 → require_role이 401(fail-closed).
    with pytest.raises(HTTPException) as ei:
        rbac.require_role("", {"blue"})
    assert ei.value.status_code == 401


def test_dev_mode_bypass_only_with_explicit_optin(monkeypatch):
    # RBAC_ALLOW_INSECURE_DEV=true 를 명시했을 때만 dev 우회 허용(로컬 개발용).
    monkeypatch.setenv("RBAC_ALLOW_INSECURE_DEV", "true")
    assert rbac.require_role("", {"blue"}).dev_mode is True


# --- 단일 instructor 토큰(하위호환) -----------------------------------------

def test_instructor_token_valid(monkeypatch):
    monkeypatch.setenv("INSTRUCTOR_TOKEN", "itok")
    ident = rbac.require_role(_bearer("itok"), {"instructor"})
    assert ident.role == "instructor"
    assert ident.dev_mode is False


def test_missing_token_when_configured_is_401(monkeypatch):
    monkeypatch.setenv("INSTRUCTOR_TOKEN", "itok")
    with pytest.raises(HTTPException) as ei:
        rbac.require_role("", {"instructor"})
    assert ei.value.status_code == 401


def test_wrong_token_is_401(monkeypatch):
    monkeypatch.setenv("INSTRUCTOR_TOKEN", "itok")
    with pytest.raises(HTTPException) as ei:
        rbac.require_role(_bearer("nope"), {"instructor"})
    assert ei.value.status_code == 401


# --- 역할 구분(403) ---------------------------------------------------------

def test_blue_token_denied_on_instructor_endpoint(monkeypatch):
    monkeypatch.setenv("INSTRUCTOR_TOKEN", "itok")
    monkeypatch.setenv("BLUE_TOKEN", "btok")
    with pytest.raises(HTTPException) as ei:
        rbac.require_role(_bearer("btok"), {"instructor"})
    assert ei.value.status_code == 403


def test_blue_token_allowed_on_defense_endpoint(monkeypatch):
    monkeypatch.setenv("INSTRUCTOR_TOKEN", "itok")
    monkeypatch.setenv("BLUE_TOKEN", "btok")
    ident = rbac.require_role(_bearer("btok"), {"instructor", "blue"})
    assert ident.role == "blue"


def test_red_token_denied_on_defense_endpoint(monkeypatch):
    monkeypatch.setenv("BLUE_TOKEN", "btok")
    monkeypatch.setenv("RED_TOKEN", "rtok")
    with pytest.raises(HTTPException) as ei:
        rbac.require_role(_bearer("rtok"), {"instructor", "blue"})
    assert ei.value.status_code == 403


# --- RBAC_TOKENS 병합 파싱 --------------------------------------------------

def test_rbac_tokens_multi_map(monkeypatch):
    monkeypatch.setenv("RBAC_TOKENS", "a1:instructor, b2:blue , r3:red")
    assert rbac.authenticate(_bearer("a1")).role == "instructor"
    assert rbac.authenticate(_bearer("b2")).role == "blue"
    assert rbac.authenticate(_bearer("r3")).role == "red"


def test_rbac_tokens_ignores_unknown_role(monkeypatch):
    monkeypatch.setenv("RBAC_TOKENS", "x:superadmin")   # 유효하지 않은 역할 → 무시
    # 매핑이 비어 dev 모드로 falls back
    assert rbac.authenticate(_bearer("x")).dev_mode is True


# --- 관전자 read 게이트(require_read / read_enforced) -----------------------

def test_read_gate_off_by_default(monkeypatch):
    """OBSERVER_READ_ENFORCE 미설정 → read_enforced False, require_read는 게이트 없음(None)."""
    monkeypatch.setenv("OBSERVER_TOKEN", "obs")  # 토큰이 있어도 플래그 없으면 공개
    assert rbac.read_enforced() is False
    assert rbac.require_read("") is None                 # 무토큰도 통과
    assert rbac.require_read(_bearer("obs")) is None


@pytest.mark.parametrize("val", ["1", "true", "TRUE", "yes", "on"])
def test_read_enforced_truthy_values(monkeypatch, val):
    monkeypatch.setenv("OBSERVER_READ_ENFORCE", val)
    assert rbac.read_enforced() is True


def test_read_gate_on_requires_any_valid_token(monkeypatch):
    """플래그 on + 토큰 설정 → 무효/누락 토큰 401, 유효 토큰(관전자 포함)은 역할 무관 통과."""
    monkeypatch.setenv("OBSERVER_READ_ENFORCE", "true")
    monkeypatch.setenv("OBSERVER_TOKEN", "obs")
    monkeypatch.setenv("RED_TOKEN", "red")
    # 무토큰 → 401
    with pytest.raises(HTTPException) as e:
        rbac.require_read("")
    assert e.value.status_code == 401
    # 관전자 토큰 → 통과(read는 관전자 이상이면 OK)
    assert rbac.require_read(_bearer("obs")).role == "observer"
    # red 토큰도 read는 허용(인증된 아무 역할)
    assert rbac.require_read(_bearer("red")).role == "red"


def test_read_gate_on_but_no_tokens_fails_closed(monkeypatch):
    """읽기 게이트 on + 토큰 미설정 + opt-in 없음 → fail-closed 401(과거엔 dev 통과였음)."""
    monkeypatch.setenv("OBSERVER_READ_ENFORCE", "true")
    with pytest.raises(HTTPException) as ei:
        rbac.require_read("")
    assert ei.value.status_code == 401


def test_read_gate_dev_pass_with_explicit_optin(monkeypatch):
    """읽기 게이트 on + RBAC_ALLOW_INSECURE_DEV 명시 → 로컬 편의로 dev 통과."""
    monkeypatch.setenv("OBSERVER_READ_ENFORCE", "true")
    monkeypatch.setenv("RBAC_ALLOW_INSECURE_DEV", "true")
    ident = rbac.require_read("")
    assert ident is not None and ident.dev_mode is True
