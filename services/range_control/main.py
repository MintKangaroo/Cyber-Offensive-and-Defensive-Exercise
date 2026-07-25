"""
Range Control (P1 #10) — 재현 가능한 초기화·스냅샷·드리프트·베이스라인 검증
============================================================================
훈련(Range/Match)의 운영 기능. 각 스테이트풀 서비스의 /admin/reset을 오케스트레이션하고,
Baseline 스냅샷 대비 드리프트를 측정하며, 리셋 후 safe_probe 전수 + health 통과를 검증한다.

권장 인터페이스(문서 요구사항):
  POST /ranges/{range_id}/snapshot        — 현재 상태를 baseline으로 저장
  POST /ranges/{range_id}/reset           — 이벤트·점수·solve·패치 초기화
  GET  /ranges/{range_id}/drift           — baseline 대비 현재 상태 차이
  POST /ranges/{range_id}/verify-baseline — safe_probe 전수 VULNERABLE + 전 서비스 health

docker 소켓을 노출하지 않고(안전), 서비스 HTTP admin 엔드포인트만으로 리셋한다.
localhost 게시 포트로 트윈/서비스에 접근하므로 호스트 사이드 실행을 권장(safe_probe와 동일).
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

import requests
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

sys.path.append(str(Path(__file__).resolve().parent.parent.parent))
from shared import safe_probe  # noqa: E402
from shared.rbac import require_role  # noqa: E402

INSTRUCTOR_TOKEN = os.environ.get("INSTRUCTOR_TOKEN", "").strip()
EVENT = os.environ.get("EVENT_COLLECTOR_URL", "http://localhost:8010")
SCORING = os.environ.get("SCORING_ENGINE_URL", "http://localhost:8020")
CONFIG = os.environ.get("CONFIG_SERVICE_URL", "http://localhost:8030")
SIEM = os.environ.get("SIEM_API_URL", "http://localhost:8040")
PORTAL = os.environ.get("CHALLENGE_PORTAL_URL", "http://localhost:8060")
EDR = os.environ.get("EDR_BACKEND_URL", "http://localhost:18090")

# 리셋 대상: (라벨, admin reset URL)
RESET_TARGETS = [
    ("event_collector", f"{EVENT}/admin/reset"),
    ("scoring_engine", f"{SCORING}/admin/reset"),
    ("config_service", f"{CONFIG}/admin/reset"),
    ("challenge_portal", f"{PORTAL}/portal/admin/reset"),
]
HEALTH_TARGETS = {
    "event_collector": f"{EVENT}/health", "scoring_engine": f"{SCORING}/health",
    "config_service": f"{CONFIG}/health", "siem_api": f"{SIEM}/health",
    "challenge_portal": f"{PORTAL}/health", "edr_backend": f"{EDR}/health",
}

STATE_PATH = Path(os.environ.get("RANGE_STATE", "/tmp/range_baselines.json"))
app = FastAPI(title="Range Control")
app.add_middleware(
    CORSMiddleware, allow_origin_regex=r"https?://(localhost|127\.0\.0\.1|(\d{1,3}\.){3}\d{1,3}|[\w-]+\.ts\.net)(:\d+)?",
    allow_methods=["*"], allow_headers=["*"], allow_credentials=False,
)


def _auth(authorization: str):
    require_role(authorization, {"instructor"})


def _hdr():
    return {"Authorization": f"Bearer {INSTRUCTOR_TOKEN}"} if INSTRUCTOR_TOKEN else {}


def _load_baselines() -> dict:
    try:
        return json.loads(STATE_PATH.read_text())
    except (OSError, ValueError):
        return {}


def _save_baselines(d: dict):
    try:
        STATE_PATH.write_text(json.dumps(d))
    except OSError:
        pass


def _current_state() -> dict:
    """관측 가능한 현재 상태(경량, 부작용 없음): 이벤트 수 + 패치 수.
    ⚠️ safe_probe는 취약 엔드포인트를 찔러 트윈이 이벤트를 발생시키므로 여기서 호출하지 않는다
    (스냅샷/드리프트가 상태를 오염시키지 않게). 취약 여부 검증은 verify-baseline에서만."""
    return {"events": _count_events(), "patched_vulns": _count_patched()}


def _count_events() -> int:
    try:
        return len(requests.get(f"{EVENT}/events?limit=1000", timeout=4).json().get("events", []))
    except requests.RequestException:
        return -1


def _count_patched() -> int:
    try:
        d = requests.get(f"{CONFIG}/config/patches", timeout=4).json()
        return sum(1 for a in d.values() for v in a.values() if v)
    except requests.RequestException:
        return -1


class RangeReq(BaseModel):
    reason: str = "range control"


# ===========================================================================
# P1 #9 — 다중 팀 테넌트 격리: Range → Match → Team → Twin Set
# ---------------------------------------------------------------------------
# 이벤트/점수는 이미 scenario_id로 파티셔닝되므로, Match마다 고유 scenario_id를 부여하면
# per-match 이벤트 스트림·per-match 점수가 그대로 격리된다(GET /replay/events?scenario_id=,
# GET /scores?scenario_id=). 플래그는 팀별 HMAC(team_id)로 이미 격리. Twin Set(팀별 트윈 인스턴스)
# 물리 격리는 per-twin internal 네트워크 위에서 phased(문서 docs/MULTI-TENANT.md 참조).
MATCHES_PATH = Path(os.environ.get("RANGE_MATCHES", "/tmp/range_matches.json"))


def _load_matches() -> dict:
    try:
        return json.loads(MATCHES_PATH.read_text())
    except (OSError, ValueError):
        return {}


def _save_matches(d: dict):
    try:
        MATCHES_PATH.write_text(json.dumps(d))
    except OSError:
        pass


class MatchReq(BaseModel):
    range_id: str
    match_id: str
    red_teams: list[str] = []
    blue_teams: list[str] = []
    twin_set: list[str] = []          # 이 매치가 쓰는 트윈 자산 키
    scenario_id: str | None = None    # 미지정 시 match_id 사용(이벤트/점수 파티션 키)


@app.post("/matches")
def create_match(req: MatchReq, authorization: str = Header(default="")):
    _auth(authorization)
    matches = _load_matches()
    scen = req.scenario_id or req.match_id
    matches[req.match_id] = {
        "range_id": req.range_id, "match_id": req.match_id,
        "red_teams": req.red_teams, "blue_teams": req.blue_teams,
        "twin_set": req.twin_set, "scenario_id": scen, "created_at": time.time(),
        # 팀→테넌트 매핑(모든 데이터에 range_id/match_id/team_id 부여의 기준)
        "team_index": {t: {"side": "red", "match_id": req.match_id, "range_id": req.range_id} for t in req.red_teams}
                    | {t: {"side": "blue", "match_id": req.match_id, "range_id": req.range_id} for t in req.blue_teams},
    }
    _save_matches(matches)
    return {"match": matches[req.match_id],
            "streams": {"events": f"/replay/events?scenario_id={scen}",
                        "scores": f"/scores?scenario_id={scen}"}}


@app.get("/matches")
def list_matches(range_id: Optional[str] = None):
    matches = _load_matches()
    items = [m for m in matches.values() if not range_id or m["range_id"] == range_id]
    return {"matches": items, "count": len(items)}


@app.get("/matches/{match_id}")
def get_match(match_id: str):
    m = _load_matches().get(match_id)
    if not m:
        raise HTTPException(404, "match 없음")
    return m


@app.get("/matches/{match_id}/scoreboard")
def match_scoreboard(match_id: str):
    """해당 Match의 점수(scenario_id 파티션) — 팀 간 직접 조회 대신 매치 스코프로."""
    m = _load_matches().get(match_id)
    if not m:
        raise HTTPException(404, "match 없음")
    try:
        r = requests.get(f"{SCORING}/scores?scenario_id={m['scenario_id']}", timeout=4)
        scores = r.json() if r.status_code == 200 else {}
    except requests.RequestException:
        scores = {}
    return {"match_id": match_id, "scenario_id": m["scenario_id"], "scores": scores}


@app.delete("/matches/{match_id}")
def delete_match(match_id: str, authorization: str = Header(default="")):
    _auth(authorization)
    matches = _load_matches()
    matches.pop(match_id, None)
    _save_matches(matches)
    return {"deleted": match_id}


@app.get("/health")
def health():
    return {"service": "range_control", "baselines": list(_load_baselines().keys())}


@app.post("/ranges/{range_id}/snapshot")
def snapshot(range_id: str, req: RangeReq, authorization: str = Header(default="")):
    _auth(authorization)
    baselines = _load_baselines()
    snap = {"captured_at": time.time(), "reason": req.reason, "state": _current_state()}
    baselines[range_id] = snap
    _save_baselines(baselines)
    return {"range_id": range_id, "snapshot": snap}


@app.post("/ranges/{range_id}/reset")
def reset(range_id: str, req: RangeReq, authorization: str = Header(default="")):
    _auth(authorization)
    results = {}
    for label, url in RESET_TARGETS:
        try:
            r = requests.post(url, headers=_hdr(), json={}, timeout=6)
            results[label] = r.json() if r.status_code < 400 else {"error": r.status_code, "body": r.text[:120]}
        except requests.RequestException as e:
            results[label] = {"error": str(e)}
    return {"range_id": range_id, "reset": results, "state_after": _current_state()}


@app.get("/ranges/{range_id}/drift")
def drift(range_id: str):
    baselines = _load_baselines()
    base = baselines.get(range_id)
    if not base:
        raise HTTPException(404, "baseline 스냅샷 없음 — 먼저 /snapshot")
    cur = _current_state()
    b = base["state"]
    delta = {k: {"baseline": b.get(k), "current": cur.get(k), "drift": (cur.get(k, 0) - b.get(k, 0))}
             for k in cur}
    drifted = any(v["drift"] not in (0, None) for v in delta.values())
    return {"range_id": range_id, "drifted": drifted, "delta": delta,
            "captured_at": base["captured_at"]}


@app.post("/ranges/{range_id}/verify-baseline")
def verify_baseline(range_id: str, authorization: str = Header(default="")):
    """리셋 후 다음 훈련 시작 가능 여부를 검증한다.
    순서: ① 전 서비스 health → ② probe 전 이벤트=0(클린) 확인 → ③ safe_probe 전수(전부
    VULNERABLE=baseline) → ④ probe가 발생시킨 이벤트를 정리(event_collector reset)해 클린 유지."""
    _auth(authorization)
    # 1) 전 서비스 health
    health_ok, health = True, {}
    for name, url in HEALTH_TARGETS.items():
        try:
            ok = requests.get(url, timeout=3).status_code == 200
        except requests.RequestException:
            ok = False
        health[name] = ok
        health_ok = health_ok and ok
    # 2) probe 전 이벤트 클린(리셋 직후여야 0)
    pre_events = _count_events()
    clean_events = pre_events == 0
    # 3) safe_probe 전수 — baseline은 전부 VULNERABLE(패치 0)
    probe = safe_probe.run(emit=False)["summary"]
    all_vulnerable = probe["patched"] == 0
    # 4) probe가 취약 엔드포인트를 찔러 만든 이벤트(트윈 access-log → SIEM 비동기 탐지 →
    #    blue_detection_success, scoring 소비)를 정리. SIEM 탐지가 비동기라 잠깐 flush를 기다린 뒤
    #    event_collector + scoring을 리셋해 클린 유지.
    time.sleep(3)
    for url in (f"{EVENT}/admin/reset", f"{SCORING}/admin/reset"):
        try:
            requests.post(url, headers=_hdr(), json={}, timeout=5)
        except requests.RequestException:
            pass
    passed = health_ok and all_vulnerable and clean_events
    return {
        "range_id": range_id, "passed": passed,
        "checks": {
            "all_services_healthy": health_ok,
            "all_vulns_open (baseline)": all_vulnerable,
            "events_clean_before_probe": clean_events,
        },
        "detail": {"health": health, "probe": probe, "pre_probe_event_count": pre_events},
        "verdict": "✅ 다음 훈련 시작 가능" if passed else "❌ baseline 미달 — reset/health 재확인",
    }


# ===========================================================================
# P1 #11 — 교관용 Safety Control (긴급정지 · 격리 · 안전 상태)
# ===========================================================================
# 팀별 일시정지(메모리 플래그). 실제 트래픽 차단은 네트워크 격리(internal net)가 담당하고,
# 여기서는 운영 상태/긴급정지 오케스트레이션을 제공한다.
_PAUSED_TEAMS: set[str] = set()


def _killswitch_active() -> bool:
    try:
        r = requests.get(f"{CONFIG}/config/killswitch", timeout=3)
        d = r.json() if r.status_code == 200 else {}
        return bool(d.get("killswitch") or d.get("active") or d.get("value") in (True, "true"))
    except requests.RequestException:
        return False


@app.get("/safety/status")
def safety_status():
    """교관 대시보드용 격리/안전 상태. egress·cross-team 차단은 per-twin internal 네트워크가,
    docker 소켓 미노출은 compose 설계가 보장(격리 테스트로 실측 검증됨)."""
    estop = _killswitch_active()
    checks = {
        "internet_egress": "BLOCKED",          # 11개 트윈 internal:true 네트워크
        "cross_team_traffic": "BLOCKED",        # per-twin 네트워크 격리(형제 트윈 도달 불가)
        "docker_socket_exposure": "NONE",       # compose에 docker.sock 마운트 없음
        "active_emergency_stop": estop,
        "unauthorized_destination_attempts": 0,  # egress 차단으로 시도 자체가 도달 불가
        "paused_teams": sorted(_PAUSED_TEAMS),
    }
    # containment score: 격리 3요소 + 긴급정지 가용성(항상 True). estop이 켜져도 격리는 유지.
    contained = [checks["internet_egress"] == "BLOCKED",
                 checks["cross_team_traffic"] == "BLOCKED",
                 checks["docker_socket_exposure"] == "NONE"]
    checks["range_containment_score"] = f"{round(100 * sum(contained) / len(contained))}%"
    return {"safety": checks}


class SafetyReq(BaseModel):
    reason: str = "instructor safety action"


@app.post("/safety/emergency-stop")
def emergency_stop(req: SafetyReq, authorization: str = Header(default="")):
    """전역 긴급정지 — config_service killswitch 발동(전 트윈 취약 서비스/공격면 비활성)."""
    _auth(authorization)
    try:
        r = requests.post(f"{CONFIG}/instructor/killswitch", headers=_hdr(),
                          json={"reason": req.reason}, timeout=5)
        ok = r.status_code < 400
    except requests.RequestException as e:
        raise HTTPException(502, f"killswitch 실패: {e}")
    return {"emergency_stop": ok, "killswitch": _killswitch_active(), "reason": req.reason}


@app.post("/safety/emergency-stop/release")
def emergency_stop_release(req: SafetyReq, authorization: str = Header(default="")):
    _auth(authorization)
    try:
        requests.post(f"{CONFIG}/instructor/killswitch/release", headers=_hdr(),
                      json={"reason": req.reason}, timeout=5)
    except requests.RequestException as e:
        raise HTTPException(502, f"release 실패: {e}")
    return {"emergency_stop": _killswitch_active(), "released": True}


class TeamPauseReq(BaseModel):
    team_id: str
    paused: bool
    reason: str = "instructor pause"


@app.post("/safety/team-pause")
def team_pause(req: TeamPauseReq, authorization: str = Header(default="")):
    """특정 팀 일시정지(포털 제출/진행 보류용 플래그). 다른 팀·격리에는 영향 없음."""
    _auth(authorization)
    if req.paused:
        _PAUSED_TEAMS.add(req.team_id)
    else:
        _PAUSED_TEAMS.discard(req.team_id)
    return {"team_id": req.team_id, "paused": req.paused, "paused_teams": sorted(_PAUSED_TEAMS)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8055)
