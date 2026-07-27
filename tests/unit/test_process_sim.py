"""
ICS 연속 물리 시뮬(P1-1 심화) 계약 고정.
레지스터가 순간값이 아니라 실제 공정처럼 동역학적으로 반응한다 — 터빈 RPM 은 명령값으로
slew-rate 제한을 받으며 상승하고, 냉각수 온도는 RPM(발열)·유량(냉각)에 따라 변한다.
"""
from shared.ics.process_sim import ProcessState, ProcessParams, step


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
