"""
Exercise Overview — 전(全) 팀 동시 운영 현황 집계 (대회급 격차 #3 (a))
=====================================================================
여러 매치/팀의 지표를 하나의 JSON 으로 합쳐, "한 번에 한 팀만" 보던 기존
스코어보드의 한계를 넘는 ALL-TEAMS 월보드(wallboard) 의 데이터 소스를 만든다.

소스(각 서비스의 기존 엔드포인트):
  - scoring_engine  GET /scores?scenario_id=            → red/blue 이벤트 점수
  - injects         GET /injects/scoreboard?scenario_id= → 인젝트 완료율
  - incident        GET /incidents?scenario_id=          → 미종결(open) 인시던트 수
  - noc_monitor     GET /noc/status                      → 트윈 가용성(uptime%)

설계 원칙
  - 이 모듈은 **순수 함수**다(네트워크 없음). fetch 는 main.py 가 best-effort 로 수행하고
    결과(또는 소스 다운 시 빈 dict)를 여기로 넘긴다 → mock 으로 단위 테스트 가능.
  - 한 소스가 비어 있어도(down/empty) 나머지는 그대로 집계한다(graceful degradation,
    aar_report._get_json 패턴과 동일한 정신).

주의(정직성): availability 는 "MONITORED" 지표일 뿐, 아직 가중 총점에 반영되지 않는다
  (twin availability → weighted score 통합은 명시적 후속 과제). 통합 가중 총점은
  검증 전까지 날조하지 않는다(CLAUDE.md 절대규칙 3).
"""
from __future__ import annotations

from typing import Any, Optional

OPEN_INCIDENT_STATUSES = {"new", "triage", "contained", "eradicated", "recovered"}
# incident.model.STATUSES 에서 'closed' 를 뺀 집합. closed 만 종결로 본다.


def _avg_availability(twin_set: list[str], noc_assets: dict[str, dict]) -> tuple[Optional[float], int]:
    """매치의 twin_set 중 NOC 가 실제로 모니터링 중인 자산들의 uptime_pct_1h 평균.

    반환: (availability_pct | None, monitored_count)
      - 모니터링 중인 자산이 하나도 없으면 (None, 0) → 월보드가 'N/A(unmonitored)' 로 표기.
    """
    vals: list[float] = []
    for asset in twin_set:
        a = noc_assets.get(asset)
        if not isinstance(a, dict):
            continue
        up = a.get("uptime_pct_1h")
        if isinstance(up, (int, float)):
            vals.append(float(up))
    if not vals:
        return None, 0
    return round(sum(vals) / len(vals), 2), len(vals)


def _inject_row_for(team_id: str, board: list[dict]) -> dict:
    for row in board:
        if row.get("team_id") == team_id:
            return row
    return {}


def aggregate_overview(
    matches: list[dict],
    scores_by_scenario: dict[str, dict],
    injects_by_scenario: dict[str, dict],
    incidents_by_scenario: dict[str, dict],
    noc_status: Optional[dict] = None,
    source_status: Optional[dict] = None,
) -> dict:
    """전 팀 운영 현황을 하나의 구조로 합친다.

    매개변수(모두 이미 fetch 된 원시 응답. 소스가 down 이면 호출부가 빈 dict 를 넘긴다):
      matches:               range_control 매치 레지스트리의 매치 dict 리스트.
      scores_by_scenario:    {scenario_id: {"teams": {team_id: {"red":n,"blue":n}}}}
      injects_by_scenario:   {scenario_id: {"scoreboard": [ {team_id, delivered, ...} ]}}
      incidents_by_scenario: {scenario_id: {"incidents": [ {team_id, status, ...} ]}}
      noc_status:            {"assets": {asset: {"uptime_pct_1h": float, "up": bool, ...}}}
      source_status:         {source_name: "ready"|"unavailable"} (호출부가 채움, 그대로 전달)

    반환:
      {
        "generated_at": <호출부가 채움 전에는 없음>,
        "matches": [ {match_id, range_id, scenario_id, availability_pct, twins_monitored, twin_set} ],
        "teams":   [ {match_id, range_id, scenario_id, team_id, side,
                      availability_pct, twins_monitored,
                      red_score, blue_score,
                      inject_delivered, inject_responded, inject_score_pct,
                      open_incidents} ],
        "source_status": {...},
      }
    """
    noc_assets = {}
    if isinstance(noc_status, dict):
        noc_assets = noc_status.get("assets") or {}

    match_rows: list[dict] = []
    team_rows: list[dict] = []

    for m in matches:
        match_id = m.get("match_id")
        range_id = m.get("range_id")
        scenario_id = m.get("scenario_id") or match_id
        twin_set = list(m.get("twin_set") or [])

        availability_pct, twins_monitored = _avg_availability(twin_set, noc_assets)

        match_rows.append({
            "match_id": match_id,
            "range_id": range_id,
            "scenario_id": scenario_id,
            "availability_pct": availability_pct,
            "twins_monitored": twins_monitored,
            "twin_set": twin_set,
        })

        scores = (scores_by_scenario.get(scenario_id) or {}).get("teams") or {}
        board = (injects_by_scenario.get(scenario_id) or {}).get("scoreboard") or []
        incidents = (incidents_by_scenario.get(scenario_id) or {}).get("incidents") or []

        # team_id → open incident count (closed 제외)
        open_counts: dict[str, int] = {}
        for inc in incidents:
            tid = inc.get("team_id")
            if tid is None:
                continue
            status = (inc.get("status") or "").lower()
            if status != "closed":  # closed 외 전부 open 으로 집계
                open_counts[tid] = open_counts.get(tid, 0) + 1

        team_index = m.get("team_index") or {}
        # team_index 가 없으면 red_teams/blue_teams 에서 유도(구버전 매치 호환).
        if not team_index:
            team_index = (
                {t: {"side": "red"} for t in (m.get("red_teams") or [])}
                | {t: {"side": "blue"} for t in (m.get("blue_teams") or [])}
            )

        for team_id, meta in team_index.items():
            side = (meta or {}).get("side", "")
            team_score = scores.get(team_id) or {}
            inj = _inject_row_for(team_id, board)
            team_rows.append({
                "match_id": match_id,
                "range_id": range_id,
                "scenario_id": scenario_id,
                "team_id": team_id,
                "side": side,
                "availability_pct": availability_pct,
                "twins_monitored": twins_monitored,
                "red_score": int(team_score.get("red", 0) or 0),
                "blue_score": int(team_score.get("blue", 0) or 0),
                "inject_delivered": int(inj.get("delivered", 0) or 0),
                "inject_responded": int(inj.get("responded", 0) or 0),
                "inject_score_pct": int(inj.get("score_pct", 0) or 0),
                "open_incidents": int(open_counts.get(team_id, 0)),
            })

    result: dict[str, Any] = {
        "matches": match_rows,
        "teams": team_rows,
    }
    if source_status is not None:
        result["source_status"] = source_status
    return result
