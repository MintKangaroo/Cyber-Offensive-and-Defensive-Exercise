"""
실제 Modbus/TCP PDU 처리(P1-1) 계약 고정.
트윈이 진짜 Modbus 를 말하게 하는 핵심 — 실 공격툴(mbpoll/pymodbus/metasploit)이 붙는다.
PDU 인코딩/디코딩·예외응답·쓰기 콜백을 소켓 없이 순수 검증.
"""
import struct

from shared.ics.modbus import ModbusBank, handle_pdu


def test_read_holding_registers_fc3():
    bank = ModbusBank(holding=[0] * 10)
    bank.holding[0] = 3000
    bank.holding[1] = 100
    pdu = struct.pack(">BHH", 3, 0, 2)          # FC3, start=0, qty=2
    resp = handle_pdu(bank, pdu)
    fc, bc = resp[0], resp[1]
    vals = struct.unpack(">HH", resp[2:])
    assert fc == 3 and bc == 4 and vals == (3000, 100)


def test_write_single_register_fc6_echo_and_state():
    bank = ModbusBank(holding=[0] * 10)
    pdu = struct.pack(">BHH", 6, 5, 1234)       # FC6, addr=5, value=1234
    resp = handle_pdu(bank, pdu)
    assert resp == pdu                           # FC6 는 요청을 에코
    assert bank.holding[5] == 1234               # 실제 상태 반영


def test_write_multiple_registers_fc16():
    bank = ModbusBank(holding=[0] * 10)
    body = struct.pack(">BHHB", 16, 2, 2, 4) + struct.pack(">HH", 11, 22)
    resp = handle_pdu(bank, body)
    fc, addr, qty = struct.unpack(">BHH", resp)
    assert (fc, addr, qty) == (16, 2, 2)
    assert bank.holding[2] == 11 and bank.holding[3] == 22


def test_read_coils_fc1_packs_bits():
    bank = ModbusBank(coils=[False] * 16)
    bank.coils[0] = True
    bank.coils[2] = True
    pdu = struct.pack(">BHH", 1, 0, 4)          # read 4 coils from 0
    resp = handle_pdu(bank, pdu)
    fc, bc, bits = resp[0], resp[1], resp[2]
    assert fc == 1 and bc == 1 and bits == 0b0101   # coil0 + coil2


def test_write_single_coil_fc5():
    bank = ModbusBank(coils=[False] * 8)
    pdu = struct.pack(">BHH", 5, 3, 0xFF00)     # ON
    resp = handle_pdu(bank, pdu)
    assert resp == pdu and bank.coils[3] is True


def test_illegal_function_exception():
    bank = ModbusBank(holding=[0] * 4)
    resp = handle_pdu(bank, struct.pack(">BHH", 99, 0, 1))
    assert resp[0] == (99 | 0x80) and resp[1] == 1   # exception code 1 = illegal function


def test_illegal_data_address_exception():
    bank = ModbusBank(holding=[0] * 4)
    resp = handle_pdu(bank, struct.pack(">BHH", 3, 100, 2))   # out of range
    assert resp[0] == (3 | 0x80) and resp[1] == 2    # code 2 = illegal data address


def test_write_callback_invoked():
    seen = []
    bank = ModbusBank(holding=[0] * 10, on_write=lambda kind, addr, vals: seen.append((kind, addr, vals)))
    handle_pdu(bank, struct.pack(">BHH", 6, 7, 42))
    assert seen == [("holding", 7, [42])]
