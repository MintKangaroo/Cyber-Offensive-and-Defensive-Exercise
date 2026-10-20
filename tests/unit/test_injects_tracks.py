"""
인젝트 채점 트랙(포렌식/법무/미디어) 계약 고정 (대회급 격차 #3 나머지).
=====================================================================
Locked Shields 식 다(多)카테고리 채점: 인젝트를 channel→track 으로 묶어 트랙별로 채점한다.
  - track_for: channel→track 매핑(forensics/legal/media/exec/other).
  - LIBRARY: forensics 채점 트랙 템플릿(triage/evidence/timeline) 존재 + 루브릭.
  - /injects/scoreboard: 팀별 by_track 집계 + 전팀 tracks 요약.
순수 매핑 + TestClient 종단(dispatch→respond→score→scoreboard).
"""
import os
import tempfile

os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="injects-tracks-")
for _k in ("RBAC_TOKENS", "INSTRUCTOR_TOKEN", "RED_TOKEN", "BLUE_TOKEN",
           "OBSERVER_TOKEN", "AUTH_JWT_SECRET", "OBSERVER_READ_ENFORCE"):
    os.environ.pop(_k, None)
os.environ["RBAC_ALLOW_INSECURE_DEV"] = "true"

from fastapi.testclient import TestClient

from services.injects import main as injects
from shared.injects_campaign import CHANNELS


def test_track_for_mapping():
    assert injects.track_for("forensics") == "forensics"
    assert injects.track_for("legal") == "legal"
    assert injects.track_for("regulator") == "legal"     # 규제 신고 = 법무 트랙
    assert injects.track_for("media") == "media"
    assert injects.track_for("exec") == "exec"
    assert injects.track_for("internal") == "other"      # 미매핑 → other
    assert injects.track_for("") == "other" and injects.track_for(None) == "other"


def test_forensics_channel_registered():
    assert "forensics" in CHANNELS


def test_library_has_forensics_track_with_rubrics():
    fx = [t for t in injects.LIBRARY if t["channel"] == "forensics"]
    assert {t["id"] for t in fx} >= {"forensics-triage", "forensics-evidence", "forensics-timeline"}
    for t in fx:
        assert t["rubric"] and all("criterion" in c and "max" in c for c in t["rubric"])


def _score_max(client, iid, rubric):
    """루브릭 전 항목 만점으로 채점."""
    scores = {c["criterion"]: c["max"] for c in rubric}
    r = client.post(f"/injects/{iid}/score", json={"scores": scores})
    assert r.status_code == 200, r.text
    return r.json()


def test_scoreboard_by_track_aggregation_e2e():
    client = TestClient(injects.app)
    client.post("/admin/reset")  # 격리
    team = "blue-1"
    # 포렌식 + 미디어 인젝트를 같은 팀에 배달.
    rubrics = {}
    for tpl_id in ("forensics-triage", "media-press-call"):
        r = client.post("/injects/dispatch", json={"template_id": tpl_id, "team_ids": [team], "scenario_id": "trk"})
        assert r.status_code == 200, r.text
        iid = r.json()["injects"][0]["id"]
        tpl = injects._LIB_BY_ID[tpl_id]
        client.post(f"/injects/{iid}/respond", json={"team_id": team, "response_text": "보고 제출"})
        _score_max(client, iid, tpl["rubric"])
        rubrics[tpl_id] = sum(c["max"] for c in tpl["rubric"])

    board = client.get("/injects/scoreboard", params={"scenario_id": "trk"}).json()
    row = {a["team_id"]: a for a in board["scoreboard"]}[team]

    # 팀 by_track: forensics + media 각각 만점(score_pct 100) 집계.
    assert set(row["by_track"]) >= {"forensics", "media"}
    assert row["by_track"]["forensics"]["score_pct"] == 100
    assert row["by_track"]["forensics"]["delivered"] == 1 and row["by_track"]["forensics"]["responded"] == 1
    assert row["by_track"]["media"]["score_pct"] == 100
    # 전체 합계도 만점.
    assert row["score_pct"] == 100

    # 전팀 tracks 요약: forensics·media 존재, TRACKS 순서 보존(forensics 가 media 보다 앞).
    tracks = {t["track"]: t for t in board["tracks"]}
    assert "forensics" in tracks and "media" in tracks
    order = [t["track"] for t in board["tracks"]]
    assert order.index("forensics") < order.index("media")
    assert tracks["forensics"]["score_pct"] == 100


def test_legal_track_groups_regulator_and_legal():
    client = TestClient(injects.app)
    client.post("/admin/reset")
    team = "blue-2"
    for tpl_id in ("regulator-notice", "legal-hold"):
        r = client.post("/injects/dispatch", json={"template_id": tpl_id, "team_ids": [team], "scenario_id": "lg"})
        iid = r.json()["injects"][0]["id"]
        tpl = injects._LIB_BY_ID[tpl_id]
        client.post(f"/injects/{iid}/respond", json={"team_id": team, "response_text": "x"})
        _score_max(client, iid, tpl["rubric"])
    board = client.get("/injects/scoreboard", params={"scenario_id": "lg"}).json()
    row = {a["team_id"]: a for a in board["scoreboard"]}[team]
    # regulator + legal 둘 다 legal 트랙으로 합산 → delivered 2.
    assert row["by_track"]["legal"]["delivered"] == 2
    assert row["by_track"]["legal"]["score_pct"] == 100
