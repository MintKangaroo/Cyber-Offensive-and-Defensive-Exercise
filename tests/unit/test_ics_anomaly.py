"""
ICS Modbus 이상탐지 분류(P1-1 red→blue 루프) 계약 고정.
Red 의 실제 Modbus 공격을 Blue/SIEM 이 탐지·분류(MITRE ICS)할 수 있게 한다.
"""
from shared.ics.anomaly import IcsBaseline, RegBand, classify_write


BASE = IcsBaseline(
    name="power_plant",
    registers={0: RegBand("TURBINE_RPM", low=2800, high=3600, protected=True),
               1: RegBand("COOLANT_FLOW", low=80, high=120, protected=False)},
    safety_coils={0},
)


def test_normal_write_no_finding():
    assert classify_write(BASE, "holding", 1, [100]) is None


def test_out_of_band_high_is_modify_parameter():
    f = classify_write(BASE, "holding", 0, [6000])
    assert f["technique"].startswith("T0836") and f["severity"] == "critical"
    assert f["register"] == "TURBINE_RPM"


def test_out_of_band_mild_is_high_not_critical():
    f = classify_write(BASE, "holding", 1, [140])   # 120 상한 대비 소폭 초과
    assert f is not None and f["severity"] == "high" and f["technique"].startswith("T0836")


def test_safety_interlock_disabled_is_suppression_critical():
    f = classify_write(BASE, "coil", 0, [False])
    assert f["technique"].startswith("T0878") and f["severity"] == "critical"
    assert "interlock" in f["reason"].lower()


def test_safety_interlock_enable_no_finding():
    assert classify_write(BASE, "coil", 0, [True]) is None


def test_protected_register_write_in_band_flags_unauthorized():
    # 보호 레지스터를 정상 밴드 값으로 써도 무인증 명령 자체가 신호(T0855).
    f = classify_write(BASE, "holding", 0, [3000])
    assert f is not None and f["technique"].startswith("T0855")


def test_unknown_register_write_flagged():
    f = classify_write(BASE, "holding", 9, [1])
    assert f is not None and f["severity"] in ("low", "medium")
