"""
ICS 트윈 Modbus 재사용 헬퍼(P1-1) 배선 계약 고정.
config → 뱅크 초기화·레지스터 이름 매핑·Modbus 쓰기 반영(순수, 소켓/이벤트 없이).
"""
from shared.ics.twin_modbus import _ModbusIcsTwin, ModbusIcsConfig
from shared.ics.safety import SafetyProfile
from shared.ics.anomaly import IcsBaseline, RegBand
from shared.ics.process_sim import ProcessParams
from shared.ics.modbus import handle_pdu
import struct


def _cfg():
    return ModbusIcsConfig(
        asset="test_ref", vuln_id="TST-001",
        reg_names={0: "PRESSURE", 1: "FEED"}, holding_init=[4, 50], coils_init=[True],
        cmd_reg=0, actual_reg=2, damage_reg=4, interlock_coil=0,
        safety=SafetyProfile(name="t", limits={0: {"name": "PRESSURE", "max": 8}}, interlock_coil=0),
        anomaly=IcsBaseline(name="t", registers={0: RegBand("PRESSURE", 3, 8, protected=True)}, safety_coils={0}),
        proc=ProcessParams(redline_rpm=8, nominal_rpm=0, k_heat=0.0),
        impact="overpressure")


def test_bank_initialized_from_config():
    t = _ModbusIcsTwin(_cfg())
    assert t.bank.holding[0] == 4 and t.bank.holding[1] == 50
    assert t.bank.holding[2] == 4          # actual_reg = 초기 명령값
    assert t.bank.coils[0] is True          # 인터록 초기 ON


def test_register_name_mapping():
    t = _ModbusIcsTwin(_cfg())
    assert t._target("holding", 0) == "PRESSURE"
    assert t._target("holding", 1) == "FEED"
    assert t._target("coil", 0) == "SAFETY_INTERLOCK"
    assert t._target("holding", 9) == "HR9"


def test_modbus_write_updates_bank(monkeypatch):
    # on_write 의 이벤트 발행은 네트워크 없이도 안전(try/except). 뱅크 상태 반영만 검증.
    t = _ModbusIcsTwin(_cfg())
    resp = handle_pdu(t.bank, struct.pack(">BHH", 6, 0, 12))   # FC6 write PRESSURE=12
    assert resp == struct.pack(">BHH", 6, 0, 12)
    assert t.bank.holding[0] == 12
