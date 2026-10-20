"""다팀 Red 캠페인 오케스트레이터 — 중앙 Red 셀이 N팀 × 다수 섹터를 동시 공격.

`livefire_demo` 가 단일 섹터/단일 팀 원샷이라면, 이 모듈은 하나의 Red 셀이 여러 교전
(engagement)을 조율한다:

  1) 교전들이 참조하는 **서로 다른 시나리오**를 중복 제거해 scenario_engine 에
     SERIAL 로 활성화(멱등: 409=이미 활성도 OK). 같은 시나리오를 공유하는 두 교전은
     단 한 번만 활성화된다.
  2) 각 교전의 킬체인을 **동시(ThreadPoolExecutor)** 로 fan-out — 교전별 선(先)지연 =
     index*stagger_sec 로 계단식 개시(관전 시 파도처럼 번지는 효과 + 트윈 동시부하 완화).
  3) (옵션) hold 창 동안 유지 후, 활성화했던 **서로 다른 시나리오**를 모두 비활성화.

실 엔드포인트에만 근거(발전소·병원·상수도 = 라이브 트윈). 킬체인/트윈 베이스는
`livefire_demo.SECTOR_PLANS` 를 그대로 재사용한다(허위 라이브 금지 — CLAUDE.md 규칙 3).

사용 예:
    RBAC_ALLOW_INSECURE_DEV=true python3 -m scripts.demo.redcampaign \
        --engagements team-01:power,team-02:hospital,team-03:water --hold-sec 120
    python3 -m scripts.demo.redcampaign --engagements team-01:power --dry-run
"""
from __future__ import annotations

import argparse
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from scripts.demo.livefire_demo import (
    EVENT_COLLECTOR,
    SCENARIO_ENGINE,
    SECTOR_PLANS,
    AttackStep,
    RequestsHttp,
    SectorPlan,
    drive_killchain,
    instructor_headers,
)


def _log(on_log: Optional[Callable[[str], None]], msg: str) -> None:
    (on_log or print)(msg)


@dataclass(frozen=True)
class Engagement:
    """한 교전 — 특정 팀이 특정 섹터 시나리오를 상대로 수행하는 공격.

    scenario_id/twin_base 미지정 시 SECTOR_PLANS[sector] 에서 가져온다.
    """
    team_id: str
    sector: str
    scenario_id: Optional[str] = None
    twin_base: Optional[str] = None

    def plan(self) -> SectorPlan:
        if self.sector not in SECTOR_PLANS:
            raise KeyError(f"unknown sector '{self.sector}' (known: {sorted(SECTOR_PLANS)})")
        return SECTOR_PLANS[self.sector]

    def resolved_scenario_id(self) -> str:
        return self.scenario_id or self.plan().scenario_id

    def resolved_twin_base(self) -> str:
        return (self.twin_base or self.plan().twin_base()).rstrip("/")

    def steps(self) -> tuple[AttackStep, ...]:
        return self.plan().steps


@dataclass
class EngagementResult:
    """교전 1건의 진행 요약."""
    team_id: str
    sector: str
    scenario_id: str
    steps_driven: list[str] = field(default_factory=list)
    step_status: list[int] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class CampaignResult:
    """캠페인 전체 요약 — 시나리오별 활성/비활성 + 교전별 결과."""
    activated: dict[str, bool] = field(default_factory=dict)    # scenario_id → 활성 성공
    deactivated: dict[str, bool] = field(default_factory=dict)  # scenario_id → 비활성 성공
    engagements: list[EngagementResult] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _distinct_scenarios(engagements: list[Engagement]) -> list[str]:
    """교전 등장 순서를 보존한 채 시나리오 ID 를 중복 제거."""
    seen: list[str] = []
    for e in engagements:
        sid = e.resolved_scenario_id()
        if sid not in seen:
            seen.append(sid)
    return seen


def _teams_for_scenario(engagements: list[Engagement], scenario_id: str) -> list[str]:
    teams: list[str] = []
    for e in engagements:
        if e.resolved_scenario_id() == scenario_id and e.team_id not in teams:
            teams.append(e.team_id)
    return teams


def run_campaign(
    engagements: list[Engagement],
    http: Any,
    *,
    hold_sec: float = 0.0,
    step_pause: float = 2.0,
    stagger_sec: float = 0.0,
    concurrency: int = 4,
    drive_attack: bool = True,
    sleep: Callable[[float], None] = time.sleep,
    on_log: Optional[Callable[[str], None]] = None,
) -> CampaignResult:
    """시나리오 SERIAL 활성(중복제거·멱등) → 교전 킬체인 CONCURRENT fan-out → hold → SERIAL 비활성.

    http 는 .post/.get(url, json/headers/timeout) 를 제공하는 **스레드 안전** 객체여야 한다
    (킬체인이 동시 구동되므로). 반환 CampaignResult 로 무인 검증이 가능하다.
    """
    res = CampaignResult()
    hdrs = instructor_headers()
    distinct = _distinct_scenarios(engagements)

    # 1) 서로 다른 시나리오를 SERIAL 로 활성화(멱등: 409=이미 활성).
    for sid in distinct:
        teams = _teams_for_scenario(engagements, sid)
        _log(on_log, f"▶ activate scenario '{sid}' (teams={teams}) → phase_clock 라이브")
        try:
            r = http.post(f"{SCENARIO_ENGINE}/scenario/activate",
                          json={"scenario_id": sid, "team_ids": teams},
                          headers=hdrs, timeout=8)
            code = getattr(r, "status_code", 0)
        except Exception as e:
            code = 0
            res.notes.append(f"activate '{sid}' error: {e}")
        if code == 200:
            res.activated[sid] = True
        elif code == 409:
            res.activated[sid] = True
            res.notes.append(f"scenario '{sid}' already active (409) — reusing")
        else:
            res.activated[sid] = False
            res.notes.append(f"activate '{sid}' failed: HTTP {code}")
            _log(on_log, f"  ✗ activate '{sid}' HTTP {code} — 이 시나리오 교전은 구동 생략")
        _log(on_log, f"  ✓ phase_clock → {EVENT_COLLECTOR}/internal/publish (scenario={sid})")

    # 2) 교전 킬체인을 CONCURRENT fan-out(교전별 선지연 = index*stagger_sec).
    results: list[Optional[EngagementResult]] = [None] * len(engagements)

    def _drive(idx: int, eng: Engagement) -> None:
        sid = eng.resolved_scenario_id()
        er = EngagementResult(team_id=eng.team_id, sector=eng.sector, scenario_id=sid)
        results[idx] = er
        if not res.activated.get(sid):
            er.notes.append(f"scenario '{sid}' not active — killchain skipped")
            return
        if not drive_attack:
            return
        if stagger_sec > 0 and idx > 0:
            sleep(idx * stagger_sec)
        _log(on_log, f"▶ [{eng.team_id}/{eng.sector}] killchain 개시 (scenario={sid})")
        labels, statuses, notes = drive_killchain(
            eng.steps(), http, eng.resolved_twin_base(),
            step_pause=step_pause, sleep=sleep, on_log=on_log)
        er.steps_driven.extend(labels)
        er.step_status.extend(statuses)
        er.notes.extend(notes)

    if engagements:
        workers = max(1, min(concurrency, len(engagements)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(_drive, i, e) for i, e in enumerate(engagements)]
            for f in futures:
                f.result()  # 예외 전파
    res.engagements = [r for r in results if r is not None]

    # 3) hold 창 유지(phase_clock 계속 흐름).
    if hold_sec > 0:
        _log(on_log, f"▶ hold {hold_sec:.0f}s — 콘솔에서 타이머/게이지/점수 라이브 확인")
        sleep(hold_sec)

    # 4) 서로 다른 시나리오를 SERIAL 로 비활성화(정리).
    for sid in distinct:
        _log(on_log, f"▶ deactivate scenario '{sid}'")
        try:
            r = http.post(f"{SCENARIO_ENGINE}/scenario/deactivate",
                          json={"scenario_id": sid}, headers=hdrs, timeout=8)
            code = getattr(r, "status_code", 0)
        except Exception as e:
            code = 0
            res.notes.append(f"deactivate '{sid}' error: {e}")
        res.deactivated[sid] = code in (200, 404)  # 404 = 이미 비활성
        if code not in (200, 404):
            res.notes.append(f"deactivate '{sid}' returned HTTP {code}")
        _log(on_log, f"  ✓ done (HTTP {code})")

    return res


def parse_engagements(spec: str) -> list[Engagement]:
    """`team:sector[:scenario]` 를 콤마로 나열한 CLI 스펙을 Engagement 리스트로 파싱.

    예: "team-01:power,team-02:hospital:HOSPITAL-PHI-EXFIL-01"
    """
    out: list[Engagement] = []
    for raw in spec.split(","):
        item = raw.strip()
        if not item:
            continue
        parts = item.split(":")
        if len(parts) < 2 or not parts[0] or not parts[1]:
            raise ValueError(f"잘못된 engagement 스펙 '{item}' — 'team:sector[:scenario]' 형식 필요")
        team, sector = parts[0], parts[1]
        scenario = parts[2] if len(parts) >= 3 and parts[2] else None
        out.append(Engagement(team_id=team, sector=sector, scenario_id=scenario))
    if not out:
        raise ValueError("engagement 가 하나도 없습니다")
    return out


def print_plan(engagements: list[Engagement], on_log: Optional[Callable[[str], None]] = None) -> None:
    """드라이런 — 네트워크 없이 캠페인 계획만 출력."""
    distinct = _distinct_scenarios(engagements)
    _log(on_log, f"[dry-run] engagements={len(engagements)} distinct_scenarios={len(distinct)}")
    for sid in distinct:
        teams = _teams_for_scenario(engagements, sid)
        _log(on_log, f"  activate   POST {SCENARIO_ENGINE}/scenario/activate  scenario={sid} teams={teams}")
    for i, e in enumerate(engagements):
        sid = e.resolved_scenario_id()
        _log(on_log, f"  [{i}] {e.team_id} · {e.sector} · {sid} @ {e.resolved_twin_base()}")
        for j, s in enumerate(e.steps(), 1):
            _log(on_log, f"       [{j}] {s.method} {s.path} {s.body}  (+{s.points}, {s.phase})")
    for sid in distinct:
        _log(on_log, f"  deactivate POST {SCENARIO_ENGINE}/scenario/deactivate  scenario={sid}")


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="다팀 Red 캠페인 오케스트레이터")
    p.add_argument("--engagements", required=True,
                   help="team:sector[:scenario] 를 콤마로 나열(예: team-01:power,team-02:hospital)")
    p.add_argument("--hold-sec", type=float, default=0.0, help="캠페인 hold 창(초)")
    p.add_argument("--step-pause", type=float, default=2.0, help="킬체인 단계 간 대기(초)")
    p.add_argument("--stagger-sec", type=float, default=0.0, help="교전별 계단식 개시 간격(초)")
    p.add_argument("--concurrency", type=int, default=4, help="동시 구동할 교전 수")
    p.add_argument("--no-attack", action="store_true", help="공격 미구동 — 타이머만 라이브")
    p.add_argument("--dry-run", action="store_true", help="네트워크 없이 계획만 출력")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    import os

    args = build_arg_parser().parse_args(argv)
    try:
        engagements = parse_engagements(args.engagements)
    except ValueError as e:
        print(f"✗ {e}", file=sys.stderr)
        return 2

    if args.dry_run:
        print_plan(engagements)
        return 0

    if not instructor_headers() and os.environ.get("RBAC_ALLOW_INSECURE_DEV", "").lower() not in ("1", "true", "yes", "on"):
        print("⚠️  INSTRUCTOR_TOKEN 미설정이고 RBAC_ALLOW_INSECURE_DEV 도 꺼져 있음 → /scenario/activate 가 거부될 수 있음",
              file=sys.stderr)

    res = run_campaign(
        engagements, RequestsHttp(),
        hold_sec=args.hold_sec, step_pause=args.step_pause,
        stagger_sec=args.stagger_sec, concurrency=args.concurrency,
        drive_attack=not args.no_attack)

    print("\n── 캠페인 요약 ─────────────────────────")
    print(f"  activated={res.activated}")
    print(f"  deactivated={res.deactivated}")
    for er in res.engagements:
        print(f"  [{er.team_id}/{er.sector}] scenario={er.scenario_id} "
              f"steps={len(er.steps_driven)} status={er.step_status}")
    for n in res.notes:
        print(f"  note: {n}")
    all_act = all(res.activated.values()) if res.activated else False
    all_deact = all(res.deactivated.values()) if res.deactivated else False
    return 0 if (all_act and all_deact) else 1


if __name__ == "__main__":
    raise SystemExit(main())
