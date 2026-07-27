"""
ICS 킬체인 시나리오 러너 런타임 검증.
저작한 POWERPLANT-MODBUS-SABOTAGE-01 을 실제 SingleScenarioTracker 에 통과시켜, Modbus 공격이
내는 이벤트(PP-002 접근 → PP-006 인터록OFF → PP-006 asset_compromised)로 스테이지 자동판정·
점수·chain_bonus 가 성립함을 못박는다.
"""
import asyncio

from services.scenario_engine.loader import load_scenario_file
from services.scenario_engine.runner import make_tracker

SCENARIO = "scenarios/single/POWERPLANT-MODBUS-SABOTAGE-01.yaml"


def _run(events):
    """이벤트 리스트를 러너에 순서대로 흘리고, 러너가 발행한 이벤트를 수집해 반환."""
    emitted = []

    async def _emit(**kw):
        emitted.append(kw)

    async def _go():
        tracker = make_tracker(load_scenario_file(SCENARIO), _emit)
        for e in events:
            await tracker.process_event(e)

    asyncio.run(_go())
    return emitted


def _ev(etype, vuln, team="red1"):
    return {"event_type": etype, "team_id": team, "vuln_id": vuln, "target_asset": "power_plant"}


FULL_CHAIN = [
    _ev("red_attack_started", "PP-002"),      # stage 1: HMI 접근
    _ev("red_attack_started", "PP-006"),      # stage 2: SIS 인터록 OFF
    _ev("asset_compromised", "PP-006"),       # stage 3: 터빈 파괴(final)
]


def test_full_chain_completes_all_stages():
    emitted = _run(FULL_CHAIN)
    stages = [e for e in emitted if e.get("event_type").__str__().endswith("stage_completed")
              or getattr(e.get("event_type"), "value", "") == "stage_completed"]
    done = sorted(e["metadata"]["stage"] for e in stages)
    assert done == [1, 2, 3]


def test_stage_points_awarded():
    emitted = _run(FULL_CHAIN)
    pts = {e["metadata"]["stage"]: e["metadata"]["points"]
           for e in emitted if e.get("metadata", {}).get("stage") in (1, 2, 3)
           and "points" in e.get("metadata", {})}
    assert pts == {1: 25, 2: 45, 3: 80}


def test_chain_bonus_awarded_when_in_order():
    emitted = _run(FULL_CHAIN)
    assert any(e.get("metadata", {}).get("chain_bonus") == 50 for e in emitted)


def test_requires_stage_enforced_out_of_order():
    # 순서 위반: stage2(PP-006) 를 stage1 없이 먼저 → 완료되면 안 됨
    emitted = _run([_ev("red_attack_started", "PP-006")])
    completed = [e for e in emitted if e.get("metadata", {}).get("stage")]
    assert completed == []


def test_final_asset_compromised_requires_prior_stages():
    # asset_compromised(stage3) 를 앞 단계 없이 → 미완료(순서 강제)
    emitted = _run([_ev("asset_compromised", "PP-006")])
    assert not any(e.get("metadata", {}).get("stage") == 3 for e in emitted)
