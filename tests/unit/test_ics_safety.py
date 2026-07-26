"""
ICS 안전 결과 판정(P1-1 심화) 계약 고정.
실제 Modbus 쓰기가 만드는 '물리적 위험 상태'를 판정한다 — 과속·저유량·인터록 해제 등.
안전 인터록이 걸려 있으면 트립으로 '억제', 해제돼 있으면 '억제 실패(임팩트)'.
"""
from shared.ics.safety import SafetyProfile, evaluate


PP = SafetyProfile(
    name="power_plant",
    limits={0: {"name": "TURBINE_RPM", "max": 4500},
            1: {"name": "COOLANT_FLOW", "min": 50}},
    interlock_coil=0,
)


def test_no_breach_within_limits():
    breaches = evaluate(PP, holding=[3000, 100], coils=[True])
    assert breaches == []


def test_overspeed_with_interlock_engaged_is_contained():
    breaches = evaluate(PP, holding=[6000, 100], coils=[True])   # interlock ON
    assert len(breaches) == 1
    b = breaches[0]
    assert b["register"] == "TURBINE_RPM" and b["contained"] is True and b["severity"] == "high"


def test_overspeed_with_interlock_disabled_is_impact():
    breaches = evaluate(PP, holding=[6000, 100], coils=[False])  # interlock OFF
    b = breaches[0]
    assert b["contained"] is False and b["severity"] == "critical" and b["condition"] == "over_max"


def test_low_flow_breach():
    breaches = evaluate(PP, holding=[3000, 10], coils=[True])
    names = {b["register"] for b in breaches}
    assert "COOLANT_FLOW" in names
    flow = [b for b in breaches if b["register"] == "COOLANT_FLOW"][0]
    assert flow["condition"] == "under_min"


def test_multiple_breaches():
    breaches = evaluate(PP, holding=[9000, 5], coils=[False])
    assert len(breaches) == 2 and all(b["contained"] is False for b in breaches)


def test_missing_coil_treated_as_disabled():
    # 코일 배열이 짧으면 인터록 해제로 간주(보수적 = 임팩트).
    breaches = evaluate(PP, holding=[6000, 100], coils=[])
    assert breaches[0]["contained"] is False
