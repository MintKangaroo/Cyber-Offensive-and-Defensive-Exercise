"""
Scoring Engine 단위 테스트 (감사 3.8/3.9/3.4/3.6/3.1)
=====================================================
- /score/ingest 10개 이벤트 타입 분기 + 중복 채점 멱등 + _award 경합(멱등으로 보장)
- 수동조정 감사 로그(before/after) + 음수 델타 + 리셋 스냅샷(3.4)
- reconcile events.db 대조(3.6) — event_collector 조회를 monkeypatch
- First Blood + 결정론적 타이브레이크(3.9, 순수 함수)
- /score/ingest 서비스 토큰 게이트(3.1)
"""
import importlib

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def se(tmp_path, monkeypatch):
    # 서비스 토큰 게이트를 dev 통과로(무토큰 401 케이스는 별도 테스트에서 검증).
    monkeypatch.setenv("RBAC_ALLOW_INSECURE_DEV", "true")
    monkeypatch.delenv("SERVICE_TOKEN", raising=False)
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    import services.scoring_engine.main as m
    importlib.reload(m)
    m.DB_PATH = tmp_path / "scores.db"
    m.init_db()
    return m, TestClient(m.app)


def _ev(**kw):
    base = dict(event_id="e1", event_type="red_attack_started", timestamp=1000.0,
               actor="red", team_id="team01", scenario_id="s1", target_asset="power_plant",
               vuln_id="PP-001", phase="initial_access", metadata={})
    base.update(kw)
    return base


# --- 10개 이벤트 타입 분기 ---------------------------------------------------

@pytest.mark.parametrize("etype,phase,extra,exp_points", [
    ("red_attack_started", "initial_access", {}, 20),
    ("red_attack_started", "privilege_escalation", {}, 30),
    ("red_attack_started", "lateral_movement", {}, 30),
    ("flag_exfiltrated", None, {}, 50),
    ("red_objective_success", None, {}, 100),
    ("blue_patch_verified", None, {"actor": "blue"}, 50),
    ("blue_detection_success", None, {"actor": "blue"}, 20),
    ("blue_block_success", None, {"actor": "blue"}, 30),
    ("asset_recovered", None, {"actor": "blue"}, 50),
    ("stage_completed", None, {"metadata": {"points": 42}}, 42),
    ("red_stealth_bonus", None, {"metadata": {"bonus_points": 7}}, 7),
])
def test_score_ingest_branches(se, etype, phase, extra, exp_points):
    m, c = se
    ev = _ev(event_type=etype, phase=phase, event_id=f"e-{etype}", **extra)
    r = c.post("/score/ingest", json=ev)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["awarded"] is True
    assert body["points"] == exp_points


def test_duplicate_milestone_not_double_awarded(se):
    m, c = se
    ev = _ev(event_id="dup1")
    assert c.post("/score/ingest", json=ev).json()["awarded"] is True
    # 같은 milestone(team+vuln+phase) → 다른 event_id여도 재적립 안 됨(멱등, _award 경합 방어)
    ev2 = _ev(event_id="dup2")
    assert c.post("/score/ingest", json=ev2).json()["awarded"] is False
    scores = c.get("/scores", params={"scenario_id": "s1"}).json()
    assert scores["teams"]["team01"]["red"] == 20  # 한 번만


def test_unmatched_detection_awards_zero(se):
    m, c = se
    ev = _ev(event_type="unmatched_detection", actor="blue", event_id="u1")
    r = c.post("/score/ingest", json=ev).json()
    assert r["awarded"] is False and r["points"] == 0


# --- 3.4 수동조정 감사 + 음수 델타 + 리셋 스냅샷 ------------------------------

def test_adjustment_audit_before_after(se):
    m, c = se
    c.post("/score/ingest", json=_ev(event_id="a1"))  # red=20
    r = c.post("/score/adjust", json={"team_id": "team01", "scenario_id": "s1",
                                      "actor": "red", "delta": -5, "reason": "penalty"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["before_score"] == 20 and body["after_score"] == 15  # 음수 델타 반영
    adj = c.get("/scores/adjustments", params={"scenario_id": "s1"}).json()["adjustments"]
    assert len(adj) == 1 and adj[0]["reason"] == "penalty" and adj[0]["delta"] == -5


def test_reset_snapshots_before_clear(se):
    m, c = se
    c.post("/score/ingest", json=_ev(event_id="r1"))
    r = c.post("/admin/reset").json()
    assert "snapshot_id" in r and r["cleared"]["team_scores"] >= 1
    # 스냅샷 테이블에 리셋 전 점수가 남아있어야(되돌리기/감사 근거)
    conn = m.get_db()
    n = conn.execute("SELECT COUNT(*) FROM reset_snapshots").fetchone()[0]
    conn.close()
    assert n >= 1
    assert c.get("/scores", params={"scenario_id": "s1"}).json()["teams"] == {}


# --- 3.6 reconcile events.db 대조 --------------------------------------------

def test_reconcile_detects_missing_achievement(se, monkeypatch):
    m, c = se
    c.post("/score/ingest", json=_ev(event_id="present"))
    # event_collector가 스코어러블 이벤트 2개를 보고하지만 하나(lost)는 achievement 없음.
    class _R:
        def raise_for_status(self): pass
        def json(self):
            return {"events": [
                {"event_id": "present", "event_type": "red_attack_started"},
                {"event_id": "lost", "event_type": "flag_exfiltrated"},
            ]}
    monkeypatch.setattr(m, "EVENT_COLLECTOR_URL", "http://x")
    import httpx
    monkeypatch.setattr(httpx, "get", lambda *a, **k: _R())
    rep = c.get("/scores/reconcile", params={"scenario_id": "s1"}).json()
    assert rep["events_crosscheck"]["checked"] is True
    assert rep["events_crosscheck"]["scoreable_without_achievement"] == 1
    assert "lost" in rep["events_crosscheck"]["missing_event_ids"]
    assert rep["all_match"] is False       # 유실 있으면 정합성 위반
    assert rep["score_consistency"] is True  # 점수 합 자체는 일치


# --- 3.9 First Blood + 타이브레이크(순수 함수) -------------------------------

def test_first_blood_earliest_wins(se):
    m, _ = se
    ach = [
        {"category": "initial_access", "team_id": "t2", "actor": "red",
         "achievement_key": "k2", "created_at": 200.0, "points": 20},
        {"category": "initial_access", "team_id": "t1", "actor": "red",
         "achievement_key": "k1", "created_at": 100.0, "points": 20},
        {"category": "manual_adjustment", "team_id": "t1", "actor": "red",
         "achievement_key": "m1", "created_at": 50.0, "points": -5},  # 제외
    ]
    fb = m.compute_first_bloods(ach)
    assert fb["initial_access"]["team_id"] == "t1"  # 더 이른 t1


def test_ranking_is_deterministic_on_ties(se):
    m, _ = se
    ts = [{"team_id": "b", "actor": "red", "score": 50},
          {"team_id": "a", "actor": "red", "score": 50},
          {"team_id": "c", "actor": "red", "score": 30}]
    fb = {"initial_access": {"team_id": "a"}}  # a가 first blood 1개
    ranking = m.compute_ranking(ts, fb)
    assert [r["team_id"] for r in ranking] == ["a", "b", "c"]  # 동점은 FB→team_id로 결정론


# --- 3.1 서비스 토큰 게이트 --------------------------------------------------

def test_ingest_requires_service_token(tmp_path, monkeypatch):
    monkeypatch.delenv("RBAC_ALLOW_INSECURE_DEV", raising=False)
    monkeypatch.delenv("SERVICE_TOKEN", raising=False)
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    import services.scoring_engine.main as m
    importlib.reload(m)
    m.DB_PATH = tmp_path / "scores.db"; m.init_db()
    c = TestClient(m.app)
    # 토큰/opt-in 없음 → fail-closed 401
    assert c.post("/score/ingest", json=_ev()).status_code == 401
    # SERVICE_TOKEN 설정 + 올바른 토큰 → 통과
    monkeypatch.setenv("SERVICE_TOKEN", "svc-tok")
    assert c.post("/score/ingest", json=_ev(),
                  headers={"Authorization": "Bearer svc-tok"}).status_code == 200
    # 잘못된 토큰 → 401
    assert c.post("/score/ingest", json=_ev(event_id="e2"),
                  headers={"Authorization": "Bearer nope"}).status_code == 401
