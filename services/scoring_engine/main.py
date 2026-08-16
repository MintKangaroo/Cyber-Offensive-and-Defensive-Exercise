"""
Scoring Engine (제안서 10장 "점수 체계" 대응)

핵심 설계: 점수는 event_id가 아니라 achievement_key(= team+scenario+vuln+milestone)
단위로 딱 한 번만 적립됩니다. 같은 취약점을 Red가 두 번 익스플로잇해도 중복 채점되지
않고, Blue가 같은 패치를 여러 번 검증해도 중복 채점되지 않습니다.
"""

import os
import sys
import sqlite3
import math
import uuid
from pathlib import Path
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from typing import Optional

# shared.rbac 임포트(컨테이너 WORKDIR가 서비스 디렉토리라 /app을 경로에 추가).
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from shared.rbac import require_role, require_read  # noqa: E402
from shared.service_auth import require_service_token  # noqa: E402

APP_DIR = Path(__file__).parent
DB_PATH = Path(os.environ.get("DATA_DIR", str(APP_DIR))) / "scores.db"  # 볼륨 영속(P0-3)
EVENT_COLLECTOR_URL = os.environ.get("EVENT_COLLECTOR_URL", "http://event_collector:8010")

# 감사 3.6: 채점되어야 하는(=achievement를 만들어야 하는) 이벤트 타입. reconcile이 events.db와
# 대조해 '스코어러블 이벤트인데 대응 achievement가 없는' 무결성 유실을 탐지한다.
SCOREABLE_EVENT_TYPES = {
    "red_attack_started", "flag_exfiltrated", "red_objective_success",
    "blue_patch_verified", "blue_detection_success", "blue_block_success",
    "asset_recovered", "stage_completed", "red_stealth_bonus",
}

app = FastAPI(title="Scoring Engine")

# Live Fire 대시보드(로컬 dev 5174 등)가 브라우저에서 직접 /scores 등을 조회하므로 CORS 필요.
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
app.add_middleware(
    CORSMiddleware, allow_origin_regex=r"https?://(localhost|127\.0\.0\.1|(\d{1,3}\.){3}\d{1,3}|[\w-]+\.ts\.net)(:\d+)?",
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

# 제안서 10장 점수표
RED_POINTS = {
    "initial_access": 20,
    "privilege_escalation": 30,
    "lateral_movement": 30,
    "data_exfiltration": 50,   # flag_exfiltrated
    "objective": 100,          # red_objective_success
}
BLUE_POINTS = {
    "patch_verified": 50,      # blue_patch_verified
    "detection_success": 20,   # blue_detection_success
    "block_success": 30,       # blue_block_success
    "asset_recovered": 50,     # 서비스 복구
}


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    conn.row_factory = sqlite3.Row
    # 동시성/내구성(감사 3.7): WAL + busy_timeout. 채점은 event_collector 전달과 교관 조정이
    # 동시에 쓸 수 있어 락 경합을 busy_timeout으로 흡수한다.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db():
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS achievements (
            achievement_key TEXT PRIMARY KEY,
            team_id TEXT,
            scenario_id TEXT,
            actor TEXT,
            category TEXT,
            points INTEGER,
            source_event_id TEXT,
            created_at REAL DEFAULT (strftime('%s','now'))
        );
        CREATE TABLE IF NOT EXISTS team_scores (
            team_id TEXT,
            scenario_id TEXT,
            actor TEXT,
            score INTEGER DEFAULT 0,
            PRIMARY KEY (team_id, scenario_id, actor)
        );
        -- 감사 3.4: 점수 수동조정 감사 로그(actor·reason·before/after·timestamp). 분쟁 대응.
        CREATE TABLE IF NOT EXISTS score_adjustments (
            adjustment_id TEXT PRIMARY KEY,
            team_id TEXT,
            scenario_id TEXT,
            actor TEXT,
            delta INTEGER,
            before_score INTEGER,
            after_score INTEGER,
            reason TEXT,
            adjusted_by TEXT,
            created_at REAL DEFAULT (strftime('%s','now'))
        );
        -- 감사 3.4: admin_reset 이 지우기 전 team_scores 스냅샷을 남긴다(되돌리기/감사용).
        CREATE TABLE IF NOT EXISTS reset_snapshots (
            snapshot_id TEXT,
            team_id TEXT,
            scenario_id TEXT,
            actor TEXT,
            score INTEGER,
            reset_by TEXT,
            created_at REAL DEFAULT (strftime('%s','now'))
        );
        """
    )
    conn.commit()
    conn.close()


init_db()


class IncomingEvent(BaseModel):
    event_id: str
    event_type: str
    timestamp: float
    actor: str
    team_id: str = "default"
    scenario_id: str = "default"
    target_asset: str
    vuln_id: Optional[str] = None
    phase: Optional[str] = None
    trace_id: Optional[str] = None
    matched_event_id: Optional[str] = None
    challenge_id: Optional[str] = None
    schema_version: Optional[str] = None
    metadata: dict = {}


def _award(conn, team_id: str, scenario_id: str, actor: str, category: str,
           points: int, milestone: str, source_event_id: str) -> bool:
    """achievement_key가 이미 있으면 스킵(멱등), 신규면 적립. 적립 여부를 반환."""
    achievement_key = f"{team_id}:{scenario_id}:{actor}:{milestone}"
    cur = conn.execute("SELECT 1 FROM achievements WHERE achievement_key=?", (achievement_key,))
    if cur.fetchone():
        return False
    conn.execute(
        "INSERT INTO achievements (achievement_key, team_id, scenario_id, actor, category, points, source_event_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (achievement_key, team_id, scenario_id, actor, category, points, source_event_id),
    )
    conn.execute(
        """
        INSERT INTO team_scores (team_id, scenario_id, actor, score) VALUES (?, ?, ?, ?)
        ON CONFLICT(team_id, scenario_id, actor) DO UPDATE SET score = score + excluded.score
        """,
        (team_id, scenario_id, actor, points),
    )
    return True


def _dwell_bonus(metadata: dict) -> int:
    """04번 문서 3절: 빠른 탐지에 보너스. dwell = detection_ts - attack_ts.
    30초마다 1점씩 감소, 최대 +20, 최소 0. matched_event가 없으면 보너스 0(기본 점수만)."""
    matched_ts = metadata.get("_matched_timestamp")
    detection_ts = metadata.get("_detection_timestamp")  # score_ingest에서 채워줌
    if matched_ts is None or detection_ts is None:
        return 0
    dwell_sec = max(0.0, detection_ts - matched_ts)
    return max(0, 20 - math.floor(dwell_sec / 30))


# ---------------------------------------------------------------------------
# 감사 3.9: First Blood + 타이브레이크(순수 함수 — DB 없이 테스트 가능)
# ---------------------------------------------------------------------------
def compute_first_bloods(achievements: list[dict]) -> dict[str, dict]:
    """카테고리별 '최초 달성'(First Blood)을 판정. 입력은 achievements 행(dict) 목록.
    점수 0(unmatched/flagged)과 수동조정(manual_adjustment)은 제외한다.
    동점 시각이면 achievement_key 사전순으로 결정론적으로 뽑는다."""
    firsts: dict[str, dict] = {}
    ordered = sorted(
        (a for a in achievements
         if a.get("points", 0) and a.get("category") not in (None, "manual_adjustment", "unmatched_detection")),
        key=lambda a: (a.get("created_at", 0.0), a.get("achievement_key", "")),
    )
    for a in ordered:
        cat = a["category"]
        if cat not in firsts:
            firsts[cat] = {
                "team_id": a.get("team_id"), "actor": a.get("actor"),
                "achievement_key": a.get("achievement_key"),
                "at": a.get("created_at"), "points": a.get("points"),
            }
    return firsts


def compute_ranking(team_scores: list[dict], first_bloods: dict[str, dict]) -> list[dict]:
    """팀 랭킹을 결정론적으로 계산. team_scores: [{team_id,actor,score}...].
    정렬 기준(내림/오름 혼합):
      1) 총점(actor 합산) 내림차순
      2) First Blood 획득 수 내림차순(동점 시 먼저 딴 팀 우대)
      3) team_id 사전순(최종 타이브레이크 — 완전 결정론)."""
    totals: dict[str, int] = {}
    for r in team_scores:
        totals[r["team_id"]] = totals.get(r["team_id"], 0) + int(r["score"])
    fb_count: dict[str, int] = {}
    for fb in first_bloods.values():
        t = fb.get("team_id")
        if t is not None:
            fb_count[t] = fb_count.get(t, 0) + 1
    ranked = sorted(
        totals.keys(),
        key=lambda t: (-totals[t], -fb_count.get(t, 0), t),
    )
    return [{"rank": i + 1, "team_id": t, "score": totals[t],
             "first_bloods": fb_count.get(t, 0)} for i, t in enumerate(ranked)]


@app.get("/health")
def health():
    return {"status": "ok", "service": "scoring_engine"}


@app.post("/score/ingest")
def score_ingest(event: IncomingEvent, authorization: str = Header(default="")):
    # 감사 3.1: 내부 S2S 전용. 무토큰 주입 차단(참가자망에서 점수 위조 방지).
    require_service_token(authorization)
    conn = get_db()
    awarded = False
    category = None
    points = 0

    if event.event_type == "red_attack_started" and event.phase in RED_POINTS:
        category = event.phase
        points = RED_POINTS[event.phase]
        milestone = f"red:{event.vuln_id}:{event.phase}"
        awarded = _award(conn, event.team_id, event.scenario_id, "red", category, points, milestone, event.event_id)

    elif event.event_type == "flag_exfiltrated":
        category = "data_exfiltration"
        points = RED_POINTS["data_exfiltration"]
        milestone = f"red:{event.vuln_id}:data_exfiltration"
        awarded = _award(conn, event.team_id, event.scenario_id, "red", category, points, milestone, event.event_id)

    elif event.event_type == "red_objective_success":
        category = "objective"
        points = RED_POINTS["objective"]
        milestone = f"red:{event.target_asset}:objective"
        awarded = _award(conn, event.team_id, event.scenario_id, "red", category, points, milestone, event.event_id)

    elif event.event_type == "blue_patch_verified":
        category = "patch_verified"
        points = BLUE_POINTS["patch_verified"]
        milestone = f"blue:{event.vuln_id}:patch_verified"
        awarded = _award(conn, event.team_id, event.scenario_id, "blue", category, points, milestone, event.event_id)

    elif event.event_type == "blue_detection_success":
        # dwell time 보너스(04번 3절): matched_event_id로 원 공격 timestamp가 enrichment 되어 있으면
        # 빠른 탐지일수록 추가 점수. 없으면 기본 점수만.
        metadata = dict(event.metadata)
        metadata["_detection_timestamp"] = event.timestamp
        bonus = _dwell_bonus(metadata)
        category = "detection_success"
        points = BLUE_POINTS["detection_success"] + bonus
        milestone = f"blue:{event.vuln_id}:detection:{event.event_id}"  # 탐지는 반복 인정 가능하도록 event_id 포함
        awarded = _award(conn, event.team_id, event.scenario_id, "blue", category, points, milestone, event.event_id)

    elif event.event_type == "blue_block_success":
        category = "block_success"
        points = BLUE_POINTS["block_success"]
        milestone = f"blue:{event.vuln_id}:block:{event.event_id}"
        awarded = _award(conn, event.team_id, event.scenario_id, "blue", category, points, milestone, event.event_id)

    elif event.event_type == "asset_recovered":
        category = "asset_recovered"
        points = BLUE_POINTS["asset_recovered"]
        milestone = f"blue:{event.target_asset}:recovered"
        awarded = _award(conn, event.team_id, event.scenario_id, "blue", category, points, milestone, event.event_id)

    elif event.event_type == "stage_completed":
        # 시나리오 킬체인 단계 완료(services/scenario_engine/runner.py가 발행). 점수는 이벤트 metadata에 실려온다.
        category = "stage_completed"
        points = int(event.metadata.get("points", 0))
        phase_name = event.metadata.get("phase", event.scenario_id)
        stage_num = event.metadata.get("stage", event.event_id)
        milestone = f"{event.actor}:{phase_name}:stage:{stage_num}"
        awarded = _award(conn, event.team_id, event.scenario_id, event.actor, category, points, milestone, event.event_id)

    elif event.event_type == "red_stealth_bonus":
        category = "stealth_bonus"
        points = int(event.metadata.get("bonus_points", 10))
        # 공격별로 한 번만 인정(어떤 공격의 은신 성공인지는 metadata.attack_event_id 또는 vuln_id로 구분)
        origin = event.metadata.get("attack_event_id", event.vuln_id or event.event_id)
        milestone = f"red:{origin}:stealth_bonus"
        awarded = _award(conn, event.team_id, event.scenario_id, "red", category, points, milestone, event.event_id)

    elif event.event_type == "unmatched_detection":
        # 대응하는 공격 이벤트가 없는 탐지(오탐 또는 치팅 의심). 점수 적립하지 않고 감사용으로만 기록.
        category = "unmatched_detection"
        points = 0
        milestone = f"flagged:{event.event_id}"
        _award(conn, event.team_id, event.scenario_id, event.actor, category, 0, milestone, event.event_id)
        awarded = False

    conn.commit()
    conn.close()
    return {"awarded": awarded, "category": category, "points": points if awarded else 0}


@app.get("/scores")
def get_scores(scenario_id: str = "default", authorization: str = Header(default="")):
    require_read(authorization)  # 관전자 read 게이트(OBSERVER_READ_ENFORCE 시 유효)
    conn = get_db()
    rows = conn.execute(
        "SELECT team_id, actor, score FROM team_scores WHERE scenario_id=? ORDER BY team_id, actor",
        (scenario_id,),
    ).fetchall()
    conn.close()
    result: dict[str, dict[str, int]] = {}
    for r in rows:
        result.setdefault(r["team_id"], {"red": 0, "blue": 0})[r["actor"]] = r["score"]
    return {"scenario_id": scenario_id, "teams": result}


@app.get("/scores/history")
def get_history(scenario_id: str = "default", team_id: Optional[str] = None, authorization: str = Header(default="")):
    require_read(authorization)  # 관전자 read 게이트
    conn = get_db()
    query = "SELECT * FROM achievements WHERE scenario_id=?"
    params = [scenario_id]
    if team_id:
        query += " AND team_id=?"
        params.append(team_id)
    query += " ORDER BY created_at ASC"
    rows = [dict(r) for r in conn.execute(query, params).fetchall()]
    conn.close()
    return {"achievements": rows}


class ScoreAdjustRequest(BaseModel):
    team_id: str
    scenario_id: str = "default"
    actor: str          # "red" | "blue"
    delta: int          # 음수 허용(감점)
    reason: str         # 필수(감사 목적)


@app.post("/score/adjust")
def adjust_score(req: ScoreAdjustRequest, authorization: str = Header(default="")):
    """교관 수동 점수조정(24번 문서 1절, Instructor API가 호출). 감점도 허용하며,
    achievements 테이블에도 기록되므로 /scores/reconcile이 수동조정까지 자동으로
    정합성 검증 대상에 포함시킨다(별도 로직 불필요).

    RBAC(P3): 점수 직접 조작은 instructor 전용. 이전엔 무인증이라 누구나 임의 가감점이
    가능했다(점수 조작 갭). 자동 채점 경로 /score/ingest는 내부 S2S라 보호 대상 아님."""
    ident = require_role(authorization, {"instructor"})
    if not req.reason.strip():
        raise HTTPException(400, "reason is required")
    if req.actor not in ("red", "blue"):
        raise HTTPException(400, "actor must be 'red' or 'blue'")

    conn = get_db()
    adjustment_id = str(uuid.uuid4())

    def _score_of(team, scen, actor):
        row = conn.execute(
            "SELECT score FROM team_scores WHERE team_id=? AND scenario_id=? AND actor=?",
            (team, scen, actor)).fetchone()
        return row["score"] if row else 0

    before = _score_of(req.team_id, req.scenario_id, req.actor)
    conn.execute(
        "INSERT INTO achievements (achievement_key, team_id, scenario_id, actor, category, points, source_event_id) "
        "VALUES (?, ?, ?, ?, 'manual_adjustment', ?, ?)",
        (f"manual:{adjustment_id}", req.team_id, req.scenario_id, req.actor, req.delta, adjustment_id),
    )
    conn.execute(
        """
        INSERT INTO team_scores (team_id, scenario_id, actor, score) VALUES (?, ?, ?, ?)
        ON CONFLICT(team_id, scenario_id, actor) DO UPDATE SET score = score + excluded.score
        """,
        (req.team_id, req.scenario_id, req.actor, req.delta),
    )
    after = _score_of(req.team_id, req.scenario_id, req.actor)
    # 감사 3.4: 조정 감사 로그(actor·reason·before/after·timestamp·adjusted_by).
    conn.execute(
        "INSERT INTO score_adjustments (adjustment_id, team_id, scenario_id, actor, delta, "
        "before_score, after_score, reason, adjusted_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (adjustment_id, req.team_id, req.scenario_id, req.actor, req.delta,
         before, after, req.reason, getattr(ident, "actor", "instructor")),
    )
    conn.commit()
    conn.close()
    return {"adjustment_id": adjustment_id, "team_id": req.team_id, "actor": req.actor,
            "delta": req.delta, "before_score": before, "after_score": after}


@app.get("/scores/reconcile")
def reconcile(scenario_id: str = "default"):
    """점수 정합성 감사(04번 문서 4절): achievements 합계와 저장된 team_scores가 일치하는지 검증.
    분쟁 발생 시 이 엔드포인트로 "이 점수가 어떤 이벤트들의 합인가"를 역추적할 수 있다."""
    conn = get_db()
    computed = conn.execute(
        """
        SELECT team_id, actor, SUM(points) as computed_score, COUNT(*) as achievement_count
        FROM achievements
        WHERE scenario_id=? AND points != 0
        GROUP BY team_id, actor
        """,
        (scenario_id,),
    ).fetchall()
    stored = {
        (r["team_id"], r["actor"]): r["score"]
        for r in conn.execute(
            "SELECT team_id, actor, score FROM team_scores WHERE scenario_id=?", (scenario_id,)
        ).fetchall()
    }
    # 감사 3.6: events.db 대조 — 스코어러블 이벤트인데 대응 achievement(source_event_id)가
    # 없는 것을 '무결성 유실 후보'로 리포트. event_collector 조회 실패는 검사 불가로 표기.
    known_sources = {r["source_event_id"] for r in conn.execute(
        "SELECT DISTINCT source_event_id FROM achievements WHERE scenario_id=?", (scenario_id,)
    ).fetchall() if r["source_event_id"]}
    conn.close()

    events_crosscheck: dict = {"checked": False}
    try:
        import httpx
        r = httpx.get(f"{EVENT_COLLECTOR_URL}/replay/events",
                      params={"scenario_id": scenario_id}, timeout=3.0)
        r.raise_for_status()
        evs = r.json().get("events", [])
        scoreable = [e for e in evs if e.get("event_type") in SCOREABLE_EVENT_TYPES]
        missing = [e["event_id"] for e in scoreable if e.get("event_id") not in known_sources]
        events_crosscheck = {
            "checked": True,
            "total_events": len(evs),
            "scoreable_events": len(scoreable),
            "achievements_with_source": len(known_sources),
            "scoreable_without_achievement": len(missing),
            "missing_event_ids": missing[:50],   # 과다 방지 상한
        }
    except Exception as e:  # event_collector 다운/불가 → 검사 불가(오탐 방지)
        events_crosscheck = {"checked": False, "error": type(e).__name__}

    report = []
    all_match = True
    for row in computed:
        key = (row["team_id"], row["actor"])
        stored_score = stored.get(key, 0)
        match = stored_score == row["computed_score"]
        all_match = all_match and match
        report.append({
            "team_id": row["team_id"],
            "actor": row["actor"],
            "computed_from_achievements": row["computed_score"],
            "stored_team_score": stored_score,
            "achievement_count": row["achievement_count"],
            "match": match,
        })
    # 무결성 유실이 있으면 all_match도 False로 강등(스코어 합은 맞아도 유실은 정합성 위반).
    events_ok = (not events_crosscheck.get("checked")) or events_crosscheck.get("scoreable_without_achievement", 0) == 0
    return {"scenario_id": scenario_id, "all_match": all_match and events_ok,
            "score_consistency": all_match, "events_crosscheck": events_crosscheck, "detail": report}




@app.get("/scores/first-bloods")
def get_first_bloods(scenario_id: str = "default", authorization: str = Header(default="")):
    """카테고리별 First Blood(최초 달성 팀) — 감사 3.9."""
    require_read(authorization)
    conn = get_db()
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM achievements WHERE scenario_id=?", (scenario_id,)).fetchall()]
    conn.close()
    return {"scenario_id": scenario_id, "first_bloods": compute_first_bloods(rows)}


@app.get("/scores/ranking")
def get_ranking(scenario_id: str = "default", authorization: str = Header(default="")):
    """결정론적 팀 랭킹(총점 → First Blood 수 → team_id) — 감사 3.9 타이브레이크."""
    require_read(authorization)
    conn = get_db()
    ts = [dict(r) for r in conn.execute(
        "SELECT team_id, actor, score FROM team_scores WHERE scenario_id=?", (scenario_id,)).fetchall()]
    ach = [dict(r) for r in conn.execute(
        "SELECT * FROM achievements WHERE scenario_id=?", (scenario_id,)).fetchall()]
    conn.close()
    fb = compute_first_bloods(ach)
    return {"scenario_id": scenario_id, "ranking": compute_ranking(ts, fb)}


@app.get("/scores/adjustments")
def get_adjustments(scenario_id: str = "default", authorization: str = Header(default="")):
    """수동 점수조정 감사 로그 조회(감사 3.4). 분쟁 시 '누가·왜·얼마나' 역추적."""
    require_read(authorization)
    conn = get_db()
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM score_adjustments WHERE scenario_id=? ORDER BY created_at ASC",
        (scenario_id,)).fetchall()]
    conn.close()
    return {"scenario_id": scenario_id, "adjustments": rows}


@app.post("/admin/reset")
def admin_reset(authorization: str = Header(default="")):
    """훈련 초기화 — scoring_engine 상태를 비운다(instructor 인증). range_control이 오케스트레이션.
    감사 3.4: 지우기 전 team_scores 를 reset_snapshots 로 스냅샷해 되돌리기/감사 근거를 남긴다."""
    ident = require_role(authorization, {"instructor"})
    conn = get_db()
    # 1) 스냅샷(비우기 전 점수 상태 보존)
    snapshot_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO reset_snapshots (snapshot_id, team_id, scenario_id, actor, score, reset_by) "
        "SELECT ?, team_id, scenario_id, actor, score, ? FROM team_scores",
        (snapshot_id, getattr(ident, "actor", "instructor")),
    )
    # 2) 비우기(스냅샷 테이블은 보존)
    cleared = {}
    for t in ['achievements', 'team_scores', 'score_adjustments']:
        try:
            cleared[t] = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            conn.execute(f"DELETE FROM {t}")
        except Exception:
            cleared[t] = "n/a"
    conn.commit(); conn.close()
    return {"service": "scoring_engine", "cleared": cleared, "snapshot_id": snapshot_id}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8020)
