"""S-3 회귀: 서비스형 챌린지 배포 스캐폴드가 예측 가능한 기본 CHALLENGE_SECRET 을 담지 않는다.

원 결함(audit/99_final.md S-3): 그레이더/포털은 CHALLENGE_SECRET 미설정 시 fail-fast 로
정비됐으나, 서비스형 챌린지의 배포 스캐폴드(challenges/*/deploy/{Dockerfile,docker-compose.yaml})가
`ENV CHALLENGE_SECRET=<slug>-dev-secret` / `${CHALLENGE_SECRET:-<slug>-dev-secret}` 형태의
예측 가능한 기본 시크릿을 담고 있었다 → 저장소 열람만으로 해당 서비스형 플래그 위조 가능.

이 테스트는 배포 스캐폴드가 (a) dev 기본 시크릿을 담지 않고, (b) compose 는 `:?`(fail-fast)로
CHALLENGE_SECRET 을 요구함을 고정한다(도커 불필요, 순수 정적 파싱).
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHALLENGES = ROOT / "challenges"

DEV_SECRET = re.compile(r"CHALLENGE_SECRET[=:\-]{1,2}\s*[a-z0-9]+-dev-secret")
COMPOSE_SECRET = re.compile(r"\$\{CHALLENGE_SECRET(:[-?])")


def _deploy_files(glob: str):
    return sorted(CHALLENGES.glob(f"*/*/deploy/{glob}"))


def test_no_dev_secret_default_in_any_deploy_scaffold():
    offenders = []
    for f in _deploy_files("Dockerfile") + _deploy_files("*.yaml") + _deploy_files("*.yml"):
        text = f.read_text(encoding="utf-8", errors="ignore")
        if DEV_SECRET.search(text):
            offenders.append(str(f.relative_to(ROOT)))
    assert not offenders, f"배포 스캐폴드에 예측 가능한 dev CHALLENGE_SECRET 잔존: {offenders}"


def test_no_baked_env_challenge_secret_in_dockerfiles():
    offenders = []
    for f in _deploy_files("Dockerfile"):
        for ln in f.read_text(encoding="utf-8", errors="ignore").splitlines():
            s = ln.strip()
            # ENV 로 굽는 것 금지(런타임 주입만 허용). 주석(#)은 무관.
            if s.startswith("ENV") and "CHALLENGE_SECRET" in s:
                offenders.append(f"{f.relative_to(ROOT)}: {s}")
    assert not offenders, f"Dockerfile 에 CHALLENGE_SECRET 을 ENV 로 구움: {offenders}"


def test_compose_requires_secret_failfast():
    """deploy compose 에서 CHALLENGE_SECRET 을 참조한다면 반드시 `:?`(fail-fast)여야 한다(`:-` 금지)."""
    offenders = []
    for f in _deploy_files("*.yaml") + _deploy_files("*.yml"):
        for ln in f.read_text(encoding="utf-8", errors="ignore").splitlines():
            m = COMPOSE_SECRET.search(ln)
            if m and m.group(1) == ":-":
                offenders.append(f"{f.relative_to(ROOT)}: {ln.strip()}")
    assert not offenders, f"compose 가 CHALLENGE_SECRET 기본값(:-)을 허용: {offenders}"
