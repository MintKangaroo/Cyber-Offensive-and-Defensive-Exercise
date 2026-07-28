"""
ICS 연속 물리 시뮬(P1-1 심화) 계약 고정.
레지스터가 순간값이 아니라 실제 공정처럼 동역학적으로 반응한다 — 터빈 RPM 은 명령값으로
slew-rate 제한을 받으며 상승하고, 냉각수 온도는 RPM(발열)·유량(냉각)에 따라 변한다.
"""
from shared.ics.process_sim import ProcessState, ProcessParams, step, has_failed, in_danger


P = ProcessParams(slew_rpm_per_s=500, nominal_rpm=3000, ambient_temp=40,
                  k_heat=0.02, k_cool=0.5)


def test_rpm_ramps_toward_command_bounded_by_slew():
    s = ProcessState(actual_rpm=3000, coolant_temp=40)
    s2 = step(s, cmd_rpm=6000, coolant_flow=100, dt=1.0, p=P)
    # 1초에 최대 500rpm 만 상승(즉시 6000 이 되지 않음)
    assert s2.actual_rpm == 3500


def test_rpm_reaches_command_over_time_not_overshoot():
    s = ProcessState(actual_rpm=3000, coolant_temp=40)
    for _ in range(10):
        s = step(s, cmd_rpm=4000, coolant_flow=100, dt=1.0, p=P)
    assert s.actual_rpm == 4000   # 도달 후 오버슈트 없음


def test_rpm_ramps_down_toward_lower_command():
    s = ProcessState(actual_rpm=4000, coolant_temp=40)
    s2 = step(s, cmd_rpm=3000, coolant_flow=100, dt=1.0, p=P)
    assert s2.actual_rpm == 3500


def test_temp_rises_when_rpm_high_and_flow_low():
    s = ProcessState(actual_rpm=6000, coolant_temp=40)
    s2 = step(s, cmd_rpm=6000, coolant_flow=0, dt=1.0, p=P)
    assert s2.coolant_temp > 40   # 냉각 없이 고RPM → 승온


def test_temp_falls_with_high_flow():
    s = ProcessState(actual_rpm=3000, coolant_temp=90)
    s2 = step(s, cmd_rpm=3000, coolant_flow=100, dt=1.0, p=P)
    assert s2.coolant_temp < 90   # 충분한 유량 → 냉각


def test_temp_floored_at_ambient():
    s = ProcessState(actual_rpm=3000, coolant_temp=41)
    s2 = step(s, cmd_rpm=3000, coolant_flow=100, dt=10.0, p=P)
    assert s2.coolant_temp >= P.ambient_temp   # 주변 온도 아래로 안 내려감


def test_nominal_steady_state_stable_temp():
    s = ProcessState(actual_rpm=3000, coolant_temp=40)
    s2 = step(s, cmd_rpm=3000, coolant_flow=100, dt=1.0, p=P)
    # 정격 운전(3000rpm, 발열 0) → 온도 변화 미미
    assert abs(s2.coolant_temp - 40) < 1


# ── 트립 · 손상(인터록 상태에 따른 결과) ──────────────────────────────
def test_interlock_engaged_trips_at_redline_no_damage():
    # 인터록 정상: redline(4500) 초과 명령이어도 트립으로 캡, 손상 0
    s = ProcessState(actual_rpm=4400, coolant_temp=40)
    s = step(s, cmd_rpm=9000, coolant_flow=100, dt=1.0, p=P, interlock_engaged=True)
    assert s.actual_rpm == P.redline_rpm and s.damage == 0.0


def test_interlock_disabled_allows_overspeed_and_accumulates_damage():
    # 인터록 해제: 캡 없음 → redline 초과 → 손상 누적
    s = ProcessState(actual_rpm=4400, coolant_temp=40)
    s = step(s, cmd_rpm=9000, coolant_flow=100, dt=1.0, p=P, interlock_engaged=False)
    assert s.actual_rpm > P.redline_rpm and s.damage > 0.0


def test_sustained_overspeed_leads_to_failure():
    s = ProcessState(actual_rpm=6000, coolant_temp=40)
    for _ in range(200):   # 지속 과속(인터록 해제) → 누적 손상 → 파국
        s = step(s, cmd_rpm=9000, coolant_flow=0, dt=1.0, p=P, interlock_engaged=False)
    assert has_failed(s, P)


def test_engaged_interlock_never_fails():
    s = ProcessState(actual_rpm=3000, coolant_temp=40)
    for _ in range(500):
        s = step(s, cmd_rpm=9000, coolant_flow=0, dt=1.0, p=P, interlock_engaged=True)
    assert not has_failed(s, P) and s.actual_rpm == P.redline_rpm


def test_damage_heals_when_secured():
    # 인터록 재무장 + 안전 상태 → 손상이 시간에 따라 회복(재실행 가능)
    hp = ProcessParams(slew_rpm_per_s=500, nominal_rpm=3000, redline_rpm=4500, heal_rate=10)
    s = ProcessState(actual_rpm=3000, coolant_temp=40, damage=50)
    s = step(s, cmd_rpm=3000, coolant_flow=100, dt=1.0, p=hp, interlock_engaged=True)
    assert s.damage == 40   # 50 - 10*1


def test_damage_heals_fully_from_failure():
    hp = ProcessParams(nominal_rpm=3000, redline_rpm=4500, heal_rate=10)
    s = ProcessState(actual_rpm=3000, coolant_temp=40, damage=100)
    for _ in range(20):
        s = step(s, cmd_rpm=3000, coolant_flow=100, dt=1.0, p=hp, interlock_engaged=True)
    assert s.damage == 0 and not has_failed(s, hp)


def test_no_heal_while_under_attack():
    # 인터록 해제(공격 지속) 중에는 회복 없음 — 오히려 누적
    hp = ProcessParams(nominal_rpm=3000, redline_rpm=4500, heal_rate=10)
    s = ProcessState(actual_rpm=6000, coolant_temp=40, damage=50)
    s = step(s, cmd_rpm=6000, coolant_flow=100, dt=1.0, p=hp, interlock_engaged=False)
    assert s.damage > 50


def test_in_danger_predicate():
    assert in_danger(ProcessState(5000, 40, 0), P) is True      # 과속
    assert in_danger(ProcessState(3000, 130, 0), P) is True     # 과열
    assert in_danger(ProcessState(3000, 40, 5), P) is True      # 손상 진행
    assert in_danger(ProcessState(3000, 40, 0), P) is False     # 정상
