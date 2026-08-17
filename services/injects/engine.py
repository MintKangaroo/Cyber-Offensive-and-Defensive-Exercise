"""
인젝트 엔진 순수 로직(P1-4 전면 구현)
=====================================
캠페인(정해진 순서의 인젝트 시나리오)을 교관이 한 번 로드하면, 엔진이 시간·조건에 따라
자동으로 인젝트를 발사한다. 상태 없는 순수함수로 "지금 발사할 스펙"을 계산 → 테스트 용이.

세 가지 발사 방식:
  1) 시간 예약(at_sec): 캠페인 시작 후 elapsed>=at_sec 이면 발사.
  2) 트리거(trigger={after, on}): 선행 인젝트가 응답(answered)되거나 마감을 놓치면(deadline_missed) 발사.
  3) 에스컬레이션: on="deadline_missed" 트리거로 후속 인젝트를 자동 발사(마감 놓친 팀 압박).

엔진은 팀 단위로 독립 진행한다. 순수함수는 한 팀의 스펙 상태(InjectState)만 받아 결정적으로
발사 대상을 계산한다. DB/시계는 호출부(main.py)가 주입.
"""
from __future__ import annotations

from dataclasses import dataclass

TRIGGER_EVENTS = ("answered", "deadline_missed")


@dataclass(frozen=True)
class InjectState:
    """한 팀 기준, 한 스펙의 현재 상태(호출부가 DB에서 계산해 주입)."""
    fired: bool = False            # 이미 발사(인박스 배달)됨
    answered: bool = False         # 팀이 응답 제출함
    deadline_missed: bool = False  # 마감 지났고 아직 미응답


def resolve_spec(spec: dict, library_by_id: dict) -> dict:
    """스펙(라이브러리 참조 또는 인라인)을 발사에 필요한 완전한 필드로 정규화.
    template_id 가 있으면 라이브러리 값을 기본으로, 스펙의 인라인 필드가 덮어쓴다."""
    tpl = library_by_id.get(spec.get("template_id")) if spec.get("template_id") else {}
    return {
        "spec_id": spec["spec_id"],
        "template_id": spec.get("template_id", ""),
        "channel": spec.get("channel", tpl.get("channel", "internal")),
        "sender": spec.get("sender", tpl.get("from", "")),
        "subject": spec.get("subject", tpl.get("subject", "")),
        "body": spec.get("body", tpl.get("body", "")),
        "rubric": spec.get("rubric", tpl.get("rubric", [])),
        "deadline_min": int(spec.get("deadline_min", tpl.get("deadline_min", 30))),
    }


def spec_is_due(spec: dict, elapsed_sec: float, states: dict) -> bool:
    """이 스펙이 지금 발사되어야 하는가(한 팀 기준). 이미 발사됐으면 False.
    - 트리거 있음: 선행 스펙이 발사됐고 트리거 조건 충족 + elapsed>=at_sec(기본 0).
    - 트리거 없음: elapsed>=at_sec(시간 예약)."""
    sid = spec["spec_id"]
    st = states.get(sid) or InjectState()
    if st.fired:
        return False
    trig = spec.get("trigger")
    if trig:
        parent = states.get(trig.get("after"))
        if parent is None or not parent.fired:
            return False
        on = trig.get("on", "answered")
        if on == "answered":
            if not parent.answered:
                return False
        elif on == "deadline_missed":
            if not (parent.deadline_missed and not parent.answered):
                return False
        else:  # 알 수 없는 트리거 이벤트 → 발사 안 함(안전)
            return False
    return elapsed_sec >= float(spec.get("at_sec", 0))


def compute_due(specs: list[dict], elapsed_sec: float, states: dict) -> list[str]:
    """한 팀 기준, 지금 발사할 스펙 id 목록(입력 순서 유지, 결정적)."""
    return [s["spec_id"] for s in specs if spec_is_due(s, elapsed_sec, states)]


def state_from_inject(deadline_at: float, response_at: float | None, now: float) -> InjectState:
    """발사된 인젝트 한 건의 DB 값 → InjectState. 발사됐으므로 fired=True."""
    answered = response_at is not None
    return InjectState(
        fired=True,
        answered=answered,
        deadline_missed=(not answered and now > deadline_at),
    )


def campaign_progress(specs: list[dict], team_ids: list[str], fired: dict) -> dict:
    """캠페인 진행률 요약. fired = {team: {spec_id: inject_id}}."""
    total = len(specs) * max(1, len(team_ids))
    done = sum(len(fired.get(t, {})) for t in team_ids)
    return {
        "specs": len(specs),
        "teams": len(team_ids),
        "fired": done,
        "total": total,
        "pct": round(100 * done / total) if total else 0,
    }
