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

가중 총점(대회급 격차 #3 (b)): twin availability·red/blue 이벤트·인젝트·인시던트를 **단일 가중
총점(weighted_total)** 으로 합산한다. availability 가 NOC 로 실제 모니터링될 때만 점수화하고
(미모니터링이면 availability_scored=False, 기여 0), 가중치는 config(DEFAULT_WEIGHTS, 환경변수로 덮어씀)
로 노출한다 — 날조된 총점이 아니라 각 구성요소의 투명한 선형결합이다(CLAUDE.md 절대규칙 3).
Locked Shields 식: 가용성·보고(인젝트)·레드/블루 공방·인시던트 페널티를 하나의 랭킹으로.
"""
from __future__ import annotations

import os
from typing import Any, Optional

OPEN_INCIDENT_STATUSES = {"new", "triage", "contained", "eradicated", "recovered"}
# incident.model.STATUSES 에서 'closed' 를 뺀 집합. closed 만 종결로 본다.

# 단일 가중 총점의 기본 가중치(환경변수 EXERCISE_WEIGHT_* 로 덮어쓴다). 의미:
#   red/blue  : 이벤트 점수에 곱하는 배수(점수는 상한 없음 → 배수로 반영).
#   availability/inject : 0~100% 비율을 이 만점으로 환산(가용성 100%=300pt, 인젝트 100%=200pt).
#   incident_penalty : open 인시던트 1건당 감점(incident_cap 까지만).
DEFAULT_WEIGHTS: dict[str, float] = {
    "red": 1.0,
    "blue": 1.0,
    "availability": 300.0,
    "inject": 200.0,
    "incident_penalty": 10.0,
    "incident_cap": 20.0,
}

# 인젝트 트랙별 상대 중요도(가중총점 격차 #3 (b) 후속 — "트랙별 점수를 세분 반영").
# injects.main.TRACKS 와 같은 트랙 키(포렌식/법무/미디어/지휘/기타). 이 가중치는
# weights["inject"] 봉투(기본 200pt)를 트랙 **사이에** 어떻게 배분할지를 정한다:
# 팀이 실제로 채점받은 트랙들의 score_pct 를 이 가중치로 **가중평균**해 봉투에 곱한다.
#   - 기본은 모두 1.0(균등) → 어느 한 트랙이 점수 물량으로 총점을 지배하지 못한다.
#   - 운영자는 EXERCISE_INJECT_WEIGHT_<TRACK> 로 트랙별 중요도를 조정한다(예: 법무 2배).
# 팀이 안 받은 트랙은 분모에서 빠지므로, 보내지 않은 트랙 때문에 감점되지 않는다.
DEFAULT_INJECT_TRACK_WEIGHTS: dict[str, float] = {
    "forensics": 1.0,
    "legal": 1.0,
    "media": 1.0,
    "exec": 1.0,
    "other": 1.0,
}


def weights_from_env(env: Optional[dict] = None) -> dict[str, float]:
    """EXERCISE_WEIGHT_<KEY>(대문자) 환경변수로 기본 가중치를 덮어쓴다. 없으면 기본값."""
    src = env if env is not None else os.environ
    w = dict(DEFAULT_WEIGHTS)
    for k in w:
        v = src.get(f"EXERCISE_WEIGHT_{k.upper()}")
        if v is not None:
            try:
                w[k] = float(v)
            except (TypeError, ValueError):
                pass
    return w


def inject_track_weights_from_env(env: Optional[dict] = None) -> dict[str, float]:
    """EXERCISE_INJECT_WEIGHT_<TRACK>(대문자) 환경변수로 트랙 가중치를 덮어쓴다."""
    src = env if env is not None else os.environ
    w = dict(DEFAULT_INJECT_TRACK_WEIGHTS)
    for k in w:
        v = src.get(f"EXERCISE_INJECT_WEIGHT_{k.upper()}")
        if v is not None:
            try:
                w[k] = float(v)
            except (TypeError, ValueError):
                pass
    return w


def _inject_points(row: dict, weights: dict[str, float], track_weights: dict[str, float]) -> float:
    """인젝트 기여 점수.

    팀이 채점받은 트랙별 score_pct(row["inject_track_pct"]) 가 있으면 트랙 가중치로
    **가중평균**해 weights["inject"] 봉투에 곱한다(트랙별 세분 반영). 트랙 데이터가
    없거나 채점된 트랙이 하나도 없으면 전체 inject_score_pct 로 **폴백**한다(하위호환).
    """
    track_pct = row.get("inject_track_pct") or {}
    num = 0.0
    den = 0.0
    for tr, pct in track_pct.items():
        tw = track_weights.get(tr, track_weights.get("other", 1.0))
        num += tw * float(pct or 0)
        den += tw
    if den > 0:
        return (num / den) / 100.0 * weights["inject"]
    return (float(row.get("inject_score_pct", 0) or 0) / 100.0) * weights["inject"]


def compute_weighted_total(
    row: dict,
    weights: dict[str, float],
    track_weights: Optional[dict[str, float]] = None,
) -> float:
    """팀 행(aggregate_overview 가 만든 구조)의 단일 가중 총점.

    availability_pct 가 숫자일 때만(= NOC 모니터링 중) 가용성 점수를 더한다(미모니터링이면 0).
    인젝트는 트랙별 score_pct(있으면)를 track_weights 로 가중평균해 반영한다.
    """
    tw = track_weights if track_weights is not None else dict(DEFAULT_INJECT_TRACK_WEIGHTS)
    avail = row.get("availability_pct")
    avail_pts = (float(avail) / 100.0) * weights["availability"] if isinstance(avail, (int, float)) else 0.0
    inject_pts = _inject_points(row, weights, tw)
    penalty = min(int(row.get("open_incidents", 0) or 0), int(weights["incident_cap"])) * weights["incident_penalty"]
    total = (
        weights["red"] * float(row.get("red_score", 0) or 0)
        + weights["blue"] * float(row.get("blue_score", 0) or 0)
        + avail_pts
        + inject_pts
        - penalty
    )
    return round(total, 2)


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
    weights: Optional[dict] = None,
    inject_track_weights: Optional[dict] = None,
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
    w = weights if weights is not None else dict(DEFAULT_WEIGHTS)
    tw = inject_track_weights if inject_track_weights is not None else dict(DEFAULT_INJECT_TRACK_WEIGHTS)
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
            # 채점된(max_sum>0) 트랙의 score_pct 만 가중평균 대상에 담는다. 배달만 되고
            # 루브릭 없는 트랙(max_sum=0)은 전체 score_pct 와 동일하게 총점에서 제외된다.
            inject_track_pct = {
                str(trk): int(d.get("score_pct", 0) or 0)
                for trk, d in (inj.get("by_track") or {}).items()
                if isinstance(d, dict) and (d.get("max_sum") or 0) > 0
            }
            row = {
                "match_id": match_id,
                "range_id": range_id,
                "scenario_id": scenario_id,
                "team_id": team_id,
                "side": side,
                "availability_pct": availability_pct,
                "twins_monitored": twins_monitored,
                "availability_scored": isinstance(availability_pct, (int, float)),
                "red_score": int(team_score.get("red", 0) or 0),
                "blue_score": int(team_score.get("blue", 0) or 0),
                "inject_delivered": int(inj.get("delivered", 0) or 0),
                "inject_responded": int(inj.get("responded", 0) or 0),
                "inject_score_pct": int(inj.get("score_pct", 0) or 0),
                "inject_track_pct": inject_track_pct,
                "open_incidents": int(open_counts.get(team_id, 0)),
            }
            row["weighted_total"] = compute_weighted_total(row, w, tw)
            team_rows.append(row)

    # 전(全) 팀 단일 랭킹(weighted_total 내림차순, 동점은 team_id 로 안정 정렬).
    ranking = [
        {"rank": i + 1, "team_id": r["team_id"], "side": r["side"],
         "match_id": r["match_id"], "weighted_total": r["weighted_total"]}
        for i, r in enumerate(sorted(team_rows, key=lambda r: (-r["weighted_total"], r["team_id"])))
    ]

    result: dict[str, Any] = {
        "matches": match_rows,
        "teams": team_rows,
        "ranking": ranking,
        "weights": w,
        "inject_track_weights": tw,
    }
    if source_status is not None:
        result["source_status"] = source_status
    return result
