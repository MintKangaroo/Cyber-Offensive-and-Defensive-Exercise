"""Live Fire 데모 오케스트레이터 — livefire-ops 콘솔을 라이브로 깨우는 무인 진행기.

하는 일(기존에 빠져 있던 "시나리오 활성 + 킬체인 구동"의 원샷 조합):
  1) scenario_engine `/scenario/activate` 로 시나리오를 활성화 → scenario_engine 의
     `_phase_clock_loop`(1Hz)이 event_collector `/internal/publish`(topic=phase_clock)로 투영
     타임라인을 밀기 시작 → 콘솔/아레나의 타이머 3종이 라이브로 흐른다.
  2) 섹터 트윈의 실제 공격 엔드포인트를 킬체인 순서대로 호출 → 트윈 물리 게이지가 움직이고
     트윈이 event_collector 로 이벤트를 발행 → scoring_engine 채점 → collector `scores` 토픽
     → 콘솔 스코어보드/솔브로그가 라이브로 오른다.
  3) 데모 창(hold) 동안 활성 유지(타이머가 계속 흐름) 후 `/scenario/deactivate` 로 정리.

실 엔드포인트에만 근거한다(발전소=완전 라이브). 트윈이 공격 엔드포인트를 구현하지 않는 섹터는
SECTOR_PLANS 에 넣지 않는다(허위 라이브 금지 — CLAUDE.md 규칙 3).

사용 예:
    RBAC_ALLOW_INSECURE_DEV=true python3 -m scripts.demo.livefire_demo --sector power --hold-sec 120
    python3 -m scripts.demo.livefire_demo --dry-run            # 네트워크 없이 계획만 출력
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

# ── 호스트 기준 엔드포인트(서브셋 기동 시 발행 포트). 환경변수로 덮어쓸 수 있다. ──────────────
SCENARIO_ENGINE = os.environ.get("SCENARIO_ENGINE_HOST_URL", "http://localhost:8045").rstrip("/")
EVENT_COLLECTOR = os.environ.get("EVENT_COLLECTOR_HOST_URL", "http://localhost:8010").rstrip("/")
INSTRUCTOR_TOKEN = os.environ.get("INSTRUCTOR_TOKEN", "")


@dataclass(frozen=True)
class AttackStep:
    """킬체인 한 단계 — 섹터 트윈의 실제 공격 엔드포인트에 대응."""
    label: str
    phase: str
    method: str          # "GET" | "POST"
    path: str            # 트윈 상대경로(예: /api/plc/write)
    body: dict[str, Any]
    points: int


@dataclass(frozen=True)
class SectorPlan:
    """섹터 데모 계획 — 활성화할 시나리오 + 구동할 킬체인 + 트윈 베이스 URL(환경변수)."""
    sector: str
    scenario_id: str
    twin_env: str        # 트윈 호스트 URL 환경변수명
    twin_default: str    # 미설정 시 기본 호스트 URL
    steps: tuple[AttackStep, ...]

    def twin_base(self) -> str:
        return os.environ.get(self.twin_env, self.twin_default).rstrip("/")


# ── 섹터 계획(실 트윈 엔드포인트에 근거). 발전소 = 완전 라이브(물리 파국까지). ──────────────
#    경로/바디는 dashboards/livefire-ops/src/data.ts 의 power 체인 및 services/power_plant/main.py 와 일치.
SECTOR_PLANS: dict[str, SectorPlan] = {
    "power": SectorPlan(
        sector="power",
        scenario_id="POWERPLANT-MODBUS-SABOTAGE-01",
        twin_env="POWER_TWIN_HOST_URL",
        twin_default="http://localhost:8002",
        steps=(
            AttackStep("HMI 기본계정 로그인", "initial_access", "POST", "/api/hmi/login",
                       {"username": "operator", "password": "operator"}, 20),
            AttackStep("PLC 터빈 RPM 상향 → 5600", "lateral_movement", "POST", "/api/plc/write",
                       {"register": "TURBINE_RPM", "value": 5600}, 30),
            AttackStep("냉각수 유량 차단 → 30", "lateral_movement", "POST", "/api/plc/write",
                       {"register": "COOLANT_FLOW", "value": 30}, 30),
            AttackStep("안전계통(SIS) 무력화 → 과속 파국", "objective", "POST", "/api/safety/override",
                       {"override": True}, 100),
        ),
    ),
    # 병원 = 라이브(PHI 탈취 → 주입펌프 과투여 → 투약 인터록 무력화 → 과투여 파국).
    #   경로/바디는 dashboards/livefire-ops/src/data.ts 의 hospital 체인과 일치.
    "hospital": SectorPlan(
        sector="hospital",
        scenario_id="HOSPITAL-PHI-EXFIL-01",
        twin_env="HOSPITAL_TWIN_HOST_URL",
        twin_default="http://localhost:8208",
        steps=(
            AttackStep("HIS 환자정보 SQLi", "initial_access", "GET", "/api/his/patient",
                       {"id": "1 OR 1=1"}, 20),
            AttackStep("PACS 영상 IDOR 열람", "lateral_movement", "GET", "/api/pacs/study",
                       {"id": "ST-1001"}, 30),
            AttackStep("주입펌프 과투여 설정 → RATE 900", "lateral_movement", "POST", "/api/device/infusion",
                       {"device": "PUMP-07", "rate": 900}, 30),
            AttackStep("투약 안전인터록(SIS) 무력화 → 과투여 파국", "objective", "POST", "/api/safety/override",
                       {"override": True}, 100),
        ),
    ),
    # 상수도 = 라이브(SCADA 탈취 → 펌프 제어 → 염소 과투입 → 안전인터록 무력화 → 급수 오염 파국).
    #   경로/바디는 dashboards/livefire-ops/src/data.ts 의 water 체인과 일치.
    "water": SectorPlan(
        sector="water",
        scenario_id="WATER-POISON-01",
        twin_env="WATER_TWIN_HOST_URL",
        twin_default="http://localhost:8203",
        steps=(
            AttackStep("SCADA HMI 기본계정", "initial_access", "POST", "/api/hmi/login",
                       {"username": "operator", "password": "operator"}, 20),
            AttackStep("배수지 펌프 제어 탈취", "lateral_movement", "POST", "/api/pump/control",
                       {"pump": "INTAKE-1", "action": "stop"}, 30),
            AttackStep("염소 과투입 주입", "lateral_movement", "POST", "/api/dosing/chlorine",
                       {"ppm": 12}, 30),
            AttackStep("투약 안전인터록(SIS) 무력화 → 급수 오염 파국", "objective", "POST", "/api/safety/override",
                       {"override": True}, 100),
        ),
    ),
}


def instructor_headers() -> dict[str, str]:
    """교관 역할 헤더. 토큰 미설정(로컬 dev)이면 빈 헤더 — RBAC_ALLOW_INSECURE_DEV=true 시 통과."""
    return {"Authorization": f"Bearer {INSTRUCTOR_TOKEN}"} if INSTRUCTOR_TOKEN else {}


class RequestsHttp:
    """기본 HTTP 클라이언트(requests 래퍼). 테스트/드라이런은 다른 객체를 주입한다."""

    def __init__(self) -> None:
        import requests  # 지연 import — 드라이런/테스트는 requests 불필요
        self._requests = requests

    def post(self, url: str, *, json: dict, headers: dict, timeout: float):
        return self._requests.post(url, json=json, headers=headers, timeout=timeout)

    def get(self, url: str, *, headers: dict, timeout: float):
        return self._requests.get(url, headers=headers, timeout=timeout)


@dataclass
class DemoResult:
    """진행 요약(무인 데모 로그/검증용)."""
    sector: str
    scenario_id: str
    activated: bool = False
    deactivated: bool = False
    steps_driven: list[str] = field(default_factory=list)
    step_status: list[int] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _log(on_log: Optional[Callable[[str], None]], msg: str) -> None:
    (on_log or print)(msg)


def drive_killchain(
    steps: tuple[AttackStep, ...],
    http: Any,
    base: str,
    *,
    step_pause: float = 2.0,
    sleep: Callable[[float], None] = time.sleep,
    on_log: Optional[Callable[[str], None]] = None,
) -> tuple[list[str], list[int], list[str]]:
    """킬체인을 순서대로 구동 — 트윈 공격 엔드포인트를 단계별 호출.

    트윈 미도달은 정직하게 note 로 기록하고 status 0 으로 계속 진행한다(허위 라이브 금지).
    반환: (구동한 step 라벨, 각 step HTTP status, 이상 note).
    """
    labels: list[str] = []
    statuses: list[int] = []
    notes: list[str] = []
    n = len(steps)
    for i, step in enumerate(steps, 1):
        _log(on_log, f"▶ [{i}/{n}] {step.phase} · {step.label} (+{step.points})")
        try:
            if step.method == "POST":
                sr = http.post(f"{base}{step.path}", json=step.body, headers={}, timeout=5)
            else:
                sr = http.get(f"{base}{step.path}", headers={}, timeout=5)
            sc = getattr(sr, "status_code", 0)
        except Exception as e:  # 트윈 미도달 — 정직하게 기록하고 계속
            sc = 0
            notes.append(f"step '{step.label}' twin unreachable: {e}")
        labels.append(step.label)
        statuses.append(sc)
        _log(on_log, f"  → twin HTTP {sc}")
        if i < n:
            sleep(step_pause)
    return labels, statuses, notes


def run_demo(
    plan: SectorPlan,
    http: Any,
    *,
    team: str = "team-01",
    hold_sec: float = 120.0,
    step_pause: float = 2.0,
    drive_attack: bool = True,
    on_log: Optional[Callable[[str], None]] = None,
    sleep: Callable[[float], None] = time.sleep,
) -> DemoResult:
    """시나리오 활성 → (옵션)킬체인 구동 → 데모 창 유지 → 비활성.

    http 는 .post/.get(url, json/headers/timeout) 를 제공하는 객체(주입 가능 → 테스트/드라이런).
    반환 DemoResult 는 활성/구동/비활성 순서를 그대로 담아 무인 검증을 가능케 한다.
    """
    res = DemoResult(sector=plan.sector, scenario_id=plan.scenario_id)
    hdrs = instructor_headers()

    # 1) 시나리오 활성화 → phase_clock 푸시 시작(타이머 3종 라이브).
    _log(on_log, f"▶ activate scenario '{plan.scenario_id}' (team={team}) → phase_clock 라이브")
    r = http.post(f"{SCENARIO_ENGINE}/scenario/activate",
                  json={"scenario_id": plan.scenario_id, "team_ids": [team]},
                  headers=hdrs, timeout=8)
    code = getattr(r, "status_code", 0)
    if code == 200:
        res.activated = True
    elif code == 409:
        res.activated = True           # 이미 활성 — 멱등 취급(데모 재실행 허용)
        res.notes.append("scenario already active (409) — reusing")
    else:
        res.notes.append(f"activate failed: HTTP {code}")
        _log(on_log, f"  ✗ activate HTTP {code} — 중단(타이머가 안 흐름)")
        return res
    _log(on_log, f"  ✓ phase_clock loop 가 {EVENT_COLLECTOR}/internal/publish 로 푸시 중")

    # 2) 킬체인 구동 — 트윈 물리 게이지 + 이벤트/점수 라이브.
    if drive_attack:
        labels, statuses, notes = drive_killchain(
            plan.steps, http, plan.twin_base(),
            step_pause=step_pause, sleep=sleep, on_log=on_log)
        res.steps_driven.extend(labels)
        res.step_status.extend(statuses)
        res.notes.extend(notes)

    # 3) 데모 창 유지(phase_clock 이 계속 흐름).
    if hold_sec > 0:
        _log(on_log, f"▶ hold {hold_sec:.0f}s — 콘솔에서 타이머/게이지/점수 라이브 확인")
        sleep(hold_sec)

    # 4) 비활성(정리).
    _log(on_log, f"▶ deactivate scenario '{plan.scenario_id}'")
    r = http.post(f"{SCENARIO_ENGINE}/scenario/deactivate",
                  json={"scenario_id": plan.scenario_id}, headers=hdrs, timeout=8)
    code = getattr(r, "status_code", 0)
    res.deactivated = code in (200, 404)   # 404 = 이미 비활성
    if code not in (200, 404):
        res.notes.append(f"deactivate returned HTTP {code}")
    _log(on_log, f"  ✓ done (HTTP {code})")
    return res


def print_plan(plan: SectorPlan, on_log: Optional[Callable[[str], None]] = None) -> None:
    """드라이런 — 네트워크 없이 진행 계획만 출력."""
    _log(on_log, f"[dry-run] sector={plan.sector} scenario={plan.scenario_id}")
    _log(on_log, f"  activate  POST {SCENARIO_ENGINE}/scenario/activate")
    _log(on_log, f"  twin base {plan.twin_base()}")
    for i, s in enumerate(plan.steps, 1):
        _log(on_log, f"  [{i}] {s.method} {s.path} {s.body}  (+{s.points}, {s.phase})")
    _log(on_log, f"  deactivate POST {SCENARIO_ENGINE}/scenario/deactivate")


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Live Fire 데모 오케스트레이터")
    p.add_argument("--sector", default="power", choices=sorted(SECTOR_PLANS),
                   help="구동할 섹터(라이브 트윈이 있는 섹터만)")
    p.add_argument("--team", default="team-01", help="시나리오 팀 ID")
    p.add_argument("--hold-sec", type=float, default=120.0, help="데모 창 유지 시간(초)")
    p.add_argument("--step-pause", type=float, default=2.0, help="킬체인 단계 간 대기(초)")
    p.add_argument("--no-attack", action="store_true", help="공격 미구동 — 타이머만 라이브")
    p.add_argument("--dry-run", action="store_true", help="네트워크 없이 계획만 출력")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    plan = SECTOR_PLANS[args.sector]
    if args.dry_run:
        print_plan(plan)
        return 0
    if not INSTRUCTOR_TOKEN and os.environ.get("RBAC_ALLOW_INSECURE_DEV", "").lower() not in ("1", "true", "yes", "on"):
        print("⚠️  INSTRUCTOR_TOKEN 미설정이고 RBAC_ALLOW_INSECURE_DEV 도 꺼져 있음 → /scenario/activate 가 거부될 수 있음",
              file=sys.stderr)
    res = run_demo(plan, RequestsHttp(), team=args.team, hold_sec=args.hold_sec,
                   step_pause=args.step_pause, drive_attack=not args.no_attack)
    print("\n── 요약 ─────────────────────────")
    print(f"  activated={res.activated} deactivated={res.deactivated}")
    print(f"  steps={res.steps_driven}")
    print(f"  status={res.step_status}")
    for n in res.notes:
        print(f"  note: {n}")
    ok = res.activated and res.deactivated
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
