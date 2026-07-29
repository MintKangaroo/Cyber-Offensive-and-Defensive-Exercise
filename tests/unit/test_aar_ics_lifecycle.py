"""
AAR ICS 라이프사이클 종합(P2-4 확장) 계약 고정.
이벤트 스트림 → 자산별 공격/침해/방어/복구 + MTTR 집계(사후검토용).
"""
from services.aar_report.integrations import summarize_ics_lifecycle


def _ev(et, asset, ts, tech=None):
    md = {"protocol": "modbus"}
    if tech:
        md["ics_technique"] = tech
    return {"event_type": et, "target_asset": asset, "timestamp": ts, "metadata": md}


def test_empty():
    s = summarize_ics_lifecycle([])
    assert s["totals"]["ics_attacks"] == 0 and s["assets"] == {}


def test_compromise_and_recovery_mttr():
    events = [
        _ev("red_attack_started", "power_plant", 100, "T0878 (Suppression)"),
        _ev("asset_compromised", "power_plant", 150),
        _ev("blue_block_success", "power_plant", 160),
        _ev("asset_recovered", "power_plant", 400),
    ]
    s = summarize_ics_lifecycle(events)
    a = s["assets"]["power_plant"]
    assert a["attacks"] == 1 and a["compromised"] == 1 and a["blocks"] == 1 and a["recovered"] == 1
    assert a["mttr_sec"] == 250          # 400 - 150
    assert "T0878" in " ".join(a["techniques"])


def test_totals_aggregate():
    events = [
        _ev("red_attack_started", "power_plant", 100),
        _ev("asset_compromised", "power_plant", 150),
        _ev("asset_recovered", "power_plant", 300),
        _ev("red_attack_started", "water_utility", 100),
        _ev("asset_compromised", "water_utility", 120),   # 미복구
    ]
    t = summarize_ics_lifecycle(events)["totals"]
    assert t["ics_attacks"] == 2 and t["compromised_assets"] == 2 and t["recovered_assets"] == 1
    assert t["avg_mttr_sec"] == 150      # power_plant 만 복구(300-150)


def test_ignores_non_ics_assets():
    events = [{"event_type": "red_attack_started", "target_asset": "dmz", "timestamp": 1, "metadata": {}}]
    assert summarize_ics_lifecycle(events)["totals"]["ics_attacks"] == 0


def test_string_metadata_normalized():
    events = [{"event_type": "red_attack_started", "target_asset": "refinery_plant",
               "timestamp": 1, "metadata": '{"protocol":"modbus","ics_technique":"T0836 (Modify)"}'}]
    s = summarize_ics_lifecycle(events)
    assert s["assets"]["refinery_plant"]["attacks"] == 1
