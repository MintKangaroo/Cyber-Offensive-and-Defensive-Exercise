"""교관 동작 — A/D 매치 시작·상태·일시정지/재개·라운드 진행(리셋은 orchestrator 참고).

시작은 검증된 scripts.bootstrap_attack_defense_demo 를 재사용한다.
"""
from __future__ import annotations

import requests

from . import common as C

BASE = "/api/attack-defense/matches"


def _op(method: str, path: str, body: dict | None = None) -> requests.Response:
    return requests.request(method, f"{C.AD_API}{path}", json=body,
                            headers=C.instructor_headers(), timeout=30)


def start(match_id: str = "ad-demo") -> dict:
    """교관: 매치 부트스트랩+시작(멱등). 검증된 bootstrap 스크립트 재사용."""
    from scripts.bootstrap_attack_defense_demo import bootstrap
    return bootstrap(start=True)


def round_state(match_id: str = "ad-demo") -> dict:
    r = _op("GET", f"{BASE}/{match_id}/rounds/current")
    return r.json() if r.status_code == 200 else {"status": f"http_{r.status_code}"}


def finalize_round(match_id: str = "ad-demo") -> dict:
    """현재 라운드를 확정(다음 라운드로 진행) — 교관이 라운드를 넘기는 동작."""
    r = _op("POST", f"{BASE}/{match_id}/rounds/current/finalize", {"reason": "rehearsal advance"})
    return {"http": r.status_code, "body": (r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text[:120])}


def pause(match_id: str = "ad-demo") -> int:
    return _op("POST", f"{BASE}/{match_id}/pause", {"reason": "rehearsal pause"}).status_code


def resume(match_id: str = "ad-demo") -> int:
    return _op("POST", f"{BASE}/{match_id}/resume", {"reason": "rehearsal resume"}).status_code


def match_state(match_id: str = "ad-demo") -> dict:
    # public 상태(무인증) — 지연 스코어보드/서비스 상태 요약.
    try:
        r = requests.get(f"{C.AD_API}/api/attack-defense/public/matches/{match_id}/state",
                         timeout=10)
        return r.json() if r.status_code == 200 else {"status": f"http_{r.status_code}"}
    except requests.RequestException as e:
        return {"status": f"error_{type(e).__name__}"}
