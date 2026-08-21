"""
Tier-3 신규 ICS 프로토콜 모듈 인코더/파서 라운드트립 테스트.
IEC104 · EtherNet/IP CIP · BACnet · MQTT Sparkplug · GOOSE · FF-H1.
각 모듈: build_* → parse_* 왕복으로 사보타주 식별 필드 + 토큰 복원 확인.
"""
from shared.ics import iec104, enip, bacnet, mqtt_sparkplug as mqtt, goose, ff_h1

TOKEN = b"flag{token_payload_deadbeef01}"


def test_iec104_control_asdu_roundtrip():
    asdu = iec104.build_asdu(iec104.C_SC_NA_1, cot=6, common_addr=1, ioa=7, info=b"\x01" + TOKEN)
    apdu = iec104.build_i_apdu(asdu, send_seq=3)
    p = iec104.parse_apdu(apdu)
    assert p is not None
    assert p.type_id == iec104.C_SC_NA_1 and p.ioa == 7
    assert p.info[1:] == TOKEN


def test_enip_cip_setattr_roundtrip():
    cip = enip.build_cip_request(enip.SVC_SET_ATTR_SINGLE, 0x04, 101, 3, TOKEN)
    frame = enip.build_sendrrdata(cip)
    p = enip.parse_sendrrdata(frame)
    assert p is not None
    assert p.service == enip.SVC_SET_ATTR_SINGLE
    assert p.class_id == 0x04 and p.instance == 101 and p.attribute == 3
    assert p.data == TOKEN


def test_bacnet_writeproperty_roundtrip():
    frame = bacnet.build_write_property(bacnet.OBJ_ANALOG_OUTPUT, 3, TOKEN, priority=8)
    p = bacnet.parse_apdu(frame)
    assert p is not None
    assert p.service == bacnet.SVC_WRITE_PROPERTY
    assert p.obj_type == bacnet.OBJ_ANALOG_OUTPUT and p.instance == 3
    assert p.priority == 8 and p.value == TOKEN


def test_mqtt_sparkplug_publish_roundtrip():
    payload = mqtt.build_sparkplug_payload("Pump/Control/Run", TOKEN)
    pkt = mqtt.build_publish("spBv1.0/PlantA/DCMD/EdgeNode1/PumpDevice", payload)
    p = mqtt.parse_publish(pkt)
    assert p is not None
    assert "/DCMD/" in p.topic
    assert p.metric == "Pump/Control/Run" and p.body == TOKEN


def test_goose_spoofed_trip_roundtrip():
    payload = goose.build_goose("IED1/LLN0$GO$gcbTrip", "IED1/LLN0$CB_Trip",
                                st_num=5001, sq_num=0, trip=True, token=TOKEN)
    g = goose.parse_goose(payload)
    assert g is not None
    assert g["gocbRef"] == "IED1/LLN0$GO$gcbTrip"
    assert g["stNum"] == 5001 and g["trip"] is True
    assert g["token"] == TOKEN


def test_ff_h1_dlpdu_roundtrip():
    dlsdu = ff_h1.build_dlsdu(ff_h1.OP_WRITE, "FIC-201", "MODE_BLK", "OOS", TOKEN)
    frame = ff_h1.build_dlpdu(ff_h1.FC_DT, 0x24, 0x5d, dlsdu)
    d = ff_h1.parse_dlpdu(frame)
    assert d is not None
    assert d.op == ff_h1.OP_WRITE and d.src == 0x5d
    assert d.block == "FIC-201" and d.param == "MODE_BLK" and d.value == "OOS"
    assert d.token == TOKEN
