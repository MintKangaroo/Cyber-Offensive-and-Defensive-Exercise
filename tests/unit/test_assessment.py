"""
개인 단위 평가 (§5) 테스트
==========================
- individual_leaderboard: 개인별 집계·결정론적 정렬.
- team_contribution: 팀 내부 기여도(share_pct).
- 복합키(match::team) team 추출.
- challenge_portal 엔드포인트 + submit이 JWT sub를 개인 귀속하는지.
"""
import importlib

from shared.assessment import individual_leaderboard, team_contribution


SOLVES = {
    "team01": {
        "WEB-001": {"points": 100, "at": 1.0, "by": "alice"},
        "FOR-001": {"points": 150, "at": 2.0, "by": "bob"},
        "WEB-002": {"points": 100, "at": 3.0, "by": "alice"},
    },
    "match9::team02": {
        "REV-001": {"points": 200, "at": 4.0, "by": "carol"},
        "AI-001": {"points": 50, "at": 5.0},   # by 없음 → anonymous
    },
}


def test_individual_leaderboard_sorted():
    lb = individual_leaderboard(SOLVES)
    # alice: 200(2), bob: 150(1), carol: 200(1), anonymous: 50
    by_name = {r["subject"]: r for r in lb}
    assert by_name["alice"]["points"] == 200 and by_name["alice"]["solved"] == 2
    assert by_name["alice"]["challenges"] == ["WEB-001", "WEB-002"]
    assert by_name["carol"]["team"] == "team02"        # 복합키서 team 추출
    assert by_name["anonymous"]["points"] == 50
    # 점수 동점(alice 200, carol 200)은 solved desc → subject asc로 결정론적
    ranks = [r["subject"] for r in lb]
    assert ranks.index("alice") < ranks.index("carol")  # solved 2 > 1
    assert lb[0]["rank"] == 1


def test_team_contribution_share():
    tc = team_contribution(SOLVES, "team01")
    assert tc["team"] == "team01" and tc["total_points"] == 350
    members = {m["subject"]: m for m in tc["members"]}
    assert members["alice"]["share_pct"] == 57   # 200/350
    assert members["bob"]["share_pct"] == 43      # 150/350


def test_portal_records_subject_and_endpoint(tmp_path, monkeypatch):
    monkeypatch.setenv("CHALLENGE_SECRET", "x")
    monkeypatch.setenv("RBAC_ALLOW_INSECURE_DEV", "true")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    import services.challenge_portal.main as m
    importlib.reload(m)
    # solve 기록을 직접 주입(그레이더 없이 개인 귀속 로직/엔드포인트만 검증)
    m._SOLVES.clear()
    m._SOLVES["team01"] = {"WEB-001": {"points": 100, "at": 1.0, "by": "alice"}}
    from fastapi.testclient import TestClient
    c = TestClient(m.app)
    r = c.get("/portal/scoreboard/individuals")
    assert r.status_code == 200
    inds = r.json()["individuals"]
    assert any(i["subject"] == "alice" and i["points"] == 100 for i in inds)
    # subject 추출 헬퍼: 명시 subject 우선
    assert m._submitter_subject("", "eve") == "eve"
    assert m._submitter_subject("", None) == "anonymous"
