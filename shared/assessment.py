"""
개인 단위 평가 (§5 잔여: 개인 단위 평가)
==========================================
훈련 점수는 팀 단위이지만, 교관은 팀 안에서 '누가 무엇을 얼마나' 기여했는지 개인별로
평가해야 한다. 챌린지 solve 기록(팀→챌린지→{by:개인})에서 개인 리더보드/기여도를 집계한다.
순수 함수만 두어 어떤 서비스에서도 재사용/테스트가 쉽다(상태 없음).

solve 기록 형식(challenge_portal _SOLVES):
    { team_key: { challenge_id: {"points": int, "at": float, "by": subject} } }
team_key 는 "match::team" 복합키일 수 있어 team 부분만 추출해 표시한다.
"""
from __future__ import annotations


def _team_of(team_key: str) -> str:
    """복합키 'match::team' → team. 단순키는 그대로."""
    return team_key.split("::", 1)[1] if "::" in team_key else team_key


def individual_leaderboard(solves: dict[str, dict[str, dict]]) -> list[dict]:
    """개인별 기여 집계 → 점수 내림차순 리더보드(결정론적).

    반환 항목: {subject, team, solved, points, challenges:[cid...]}
    정렬: 점수 desc → solved desc → subject asc.
    """
    agg: dict[tuple[str, str], dict] = {}
    for team_key, chals in solves.items():
        team = _team_of(team_key)
        for cid, rec in chals.items():
            subject = (rec or {}).get("by") or "anonymous"
            key = (subject, team)
            slot = agg.setdefault(key, {"subject": subject, "team": team,
                                        "solved": 0, "points": 0, "challenges": []})
            slot["solved"] += 1
            slot["points"] += int((rec or {}).get("points", 0))
            slot["challenges"].append(cid)
    rows = list(agg.values())
    for r in rows:
        r["challenges"].sort()
    rows.sort(key=lambda r: (-r["points"], -r["solved"], r["subject"]))
    for i, r in enumerate(rows):
        r["rank"] = i + 1
    return rows


def team_contribution(solves: dict[str, dict[str, dict]], team_key: str) -> dict:
    """특정 팀의 개인별 기여 분해(팀 내부 평가용)."""
    members = [r for r in individual_leaderboard(solves) if r["team"] == _team_of(team_key)]
    total = sum(r["points"] for r in members)
    for r in members:
        r["share_pct"] = round(100 * r["points"] / total) if total else 0
    return {"team": _team_of(team_key), "total_points": total, "members": members}
