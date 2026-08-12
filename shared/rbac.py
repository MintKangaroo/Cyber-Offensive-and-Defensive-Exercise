"""
공유 RBAC (24번 문서 4절: 단일 INSTRUCTOR_TOKEN → 역할별 토큰으로 확장)
=========================================================================
그동안 컨트롤플레인(config_service/instructor_api/edr)은 하나의 공유 Bearer 토큰만 확인했다.
대회 규모가 커지면 교관/Red/Blue/관전자를 구분해야 한다. 여기서 토큰→역할 매핑 + 엔드포인트별
허용역할 검사를 제공한다. FastAPI에만 의존(HTTPException)하고 상태가 없어 테스트가 쉽다.

토큰 설정(둘 다 병합, 값이 비면 무시):
  1) 개별 변수: INSTRUCTOR_TOKEN / RED_TOKEN / BLUE_TOKEN / OBSERVER_TOKEN
  2) RBAC_TOKENS="tokA:instructor,tokB:blue,..." (한 역할에 여러 토큰도 가능)

인증 정책:
  - 토큰이 하나도 설정되지 않음(로컬 dev): 미인증 요청도 통과시키되 dev_mode=True로 표시하고
    모든 역할 검사를 우회한다(기존 _require_instructor의 관대한 dev 동작 보존).
  - 토큰이 설정됨(운영/CI): 유효 토큰만 해당 역할로 인증, 그 외(빈/오인증)는 401.
  - 역할이 허용집합에 없으면 403.

향후 확장: 정적 토큰 → 역할 클레임을 담은 JWT로 교체 시 이 모듈의 authenticate()만 바꾸면 된다.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

ROLES = ("instructor", "operator", "competitor", "red", "blue", "observer")


@dataclass(frozen=True)
class Identity:
    actor: str          # 감사 로그용 식별자(토큰 자체는 노출하지 않음)
    role: str           # ROLES 중 하나
    dev_mode: bool = False   # 토큰 미설정 로컬 개발 여부(역할 검사 우회)
    team_id: str = ""        # JWT 멤버십 클레임(정적 토큰에는 없음)
    match_id: str = ""       # JWT 멤버십 클레임(정적 토큰에는 없음)
    tournament_id: str = ""  # LiveCTF 상위 identity scope(선택)


def _token_role_map() -> dict[str, str]:
    """환경변수에서 토큰→역할 매핑을 로드(호출마다 읽어 테스트에서 monkeypatch 용이)."""
    mapping: dict[str, str] = {}
    for role in ROLES:
        tok = os.environ.get(f"{role.upper()}_TOKEN", "").strip()
        if tok:
            mapping[tok] = role
    raw = os.environ.get("RBAC_TOKENS", "").strip()
    if raw:
        for pair in raw.split(","):
            if ":" in pair:
                tok, role = (p.strip() for p in pair.split(":", 1))
                if tok and role in ROLES:
                    mapping[tok] = role
    return mapping


def _bearer(authorization: str) -> str:
    return (authorization or "").replace("Bearer ", "").strip()


def _jwt_secret() -> str:
    return os.environ.get("AUTH_JWT_SECRET", "").strip()


def _decode_jwt(token: str) -> Identity | None:
    """AUTH_JWT_SECRET로 서명된 JWT면 Identity로 디코드. 아니면 None(정적 토큰 등)."""
    secret = _jwt_secret()
    if not secret or token.count(".") != 2:
        return None
    try:
        import jwt  # PyJWT
        claims = jwt.decode(token, secret, algorithms=["HS256"])
    except Exception:  # 서명 불일치/만료/형식오류 → 무효 토큰
        return None
    role = claims.get("role")
    if claims.get("type") not in (None, "access") or role not in ROLES:
        return None
    return Identity(
        actor=claims.get("sub", role),
        role=role,
        team_id=str(claims.get("team_id", "") or ""),
        match_id=str(claims.get("match_id", "") or ""),
        tournament_id=str(claims.get("tournament_id", "") or ""),
    )


def authenticate(authorization: str) -> Identity:
    """Authorization 헤더 → Identity. JWT(P0-2) 또는 정적 토큰(하위호환)을 검증.
    JWT 시크릿·정적 토큰이 모두 없으면 dev 모드(로컬 편의)."""
    from fastapi import HTTPException
    mapping = _token_role_map()
    has_jwt = bool(_jwt_secret())
    token = _bearer(authorization)
    if not mapping and not has_jwt:
        # dev 모드: 인증 구성 자체가 없음 → 미인증도 instructor로 통과(dev 프로파일 전용)
        return Identity(actor="unauthenticated", role="instructor", dev_mode=True)
    # 1) JWT 우선(서명 검증)
    ident = _decode_jwt(token) if has_jwt else None
    if ident is not None:
        return ident
    # 2) 정적 토큰(하위호환)
    role = mapping.get(token)
    if role is None:
        raise HTTPException(status_code=401, detail="missing or invalid token")
    return Identity(actor=role, role=role)


def read_enforced() -> bool:
    """읽기 전용 모니터링 엔드포인트에 관전자(observer) 게이트를 적용할지 여부.

    기본값은 off — 대시보드/스모크/CI가 토큰 없이 read 엔드포인트를 그대로 쓸 수 있게
    '완전 공개' 동작을 보존한다. 운영에서 관전 접근을 통제하고 싶을 때만
    OBSERVER_READ_ENFORCE=true 로 켜면, read 엔드포인트가 '인증된 아무 역할(관전자 포함)'을
    요구하도록 세분화된다(쓰기 엔드포인트는 여전히 instructor/blue 전용).
    """
    return os.environ.get("OBSERVER_READ_ENFORCE", "").strip().lower() in ("1", "true", "yes", "on")


def require_read(authorization: str) -> Identity | None:
    """읽기 전용 모니터링 엔드포인트 게이트.

    - OBSERVER_READ_ENFORCE 미설정: None 반환(게이트 없음 = 기존 공개 동작).
    - 설정됨: 인증된 4역할(instructor/red/blue/observer) 중 아무나 허용 →
      무효/누락 토큰은 401, 유효 토큰이면 역할 무관 통과. 즉 '관전자 이상'이면 읽기 가능.
    - dev 모드(토큰 자체가 미설정): authenticate()가 dev_mode로 통과.
    """
    if not read_enforced():
        return None
    return require_role(authorization, set(ROLES))


def require_role(authorization: str, allowed: set[str]) -> Identity:
    """허용 역할 집합에 속하면 Identity 반환. 인증 실패는 401, 역할 불충분은 403.
    dev 모드(토큰 미설정)에서는 모든 검사를 우회한다."""
    from fastapi import HTTPException
    ident = authenticate(authorization)
    if ident.dev_mode:
        return ident
    if ident.role not in allowed:
        raise HTTPException(
            status_code=403,
            detail=f"role '{ident.role}' not permitted (need one of {sorted(allowed)})",
        )
    return ident
