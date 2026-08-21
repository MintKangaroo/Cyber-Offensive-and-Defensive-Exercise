"""
ICS-012 배포 생성기 — 실 MQTT Sparkplug B 사보타주 캡처(.pcap) 합성.
=====================================================================
목업 JSON 로그가 아니라 **진짜 MQTT 트래픽**을 담은 pcap 을 만든다. Wireshark 가 포트 1883 을
MQTT 로 디섹션한다(토픽·PUBLISH). 프레임은 `shared/ics/mqtt_sparkplug.py` 실 인코더로 만든다.

시나리오: 정상 SCADA(10.90.0.5)의 DDATA/NDATA 텔레메트리 PUBLISH 사이에, 무단 퍼블리셔(rogue,
팀별 IP)가 DCMD 토픽으로 펌프 액추에이터 명령(Pump/Control/Run)을 주입한 사보타주가 숨어 있다.
그 DCMD PUBLISH 의 Sparkplug body 에 토큰(= flag ⊕ 공격자 IP)이 실려 있다. 분석: DCMD 토픽으로
액추에이터 명령을 낸 정상 아닌 출발지를 찾아 공격자 IP 를 식별하고, body 를 공격자 IP 로 XOR
복호하면 flag.

팀별 공격자 IP·flag·타이밍이 HMAC 결정. 모든 값은 합성 더미(실장비/실호스트 무관).
"""
import hashlib
import hmac
import os
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))  # repo 루트(shared 임포트)

from shared.ics import mqtt_sparkplug as mqtt
from shared.net import pcap

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요.")

LEGIT = "10.90.0.5"
BROKER_IP = "10.90.0.30"
PORT = 1883
DATA_TOPIC = "spBv1.0/PlantA/DDATA/EdgeNode1/PumpDevice"
DCMD_TOPIC = "spBv1.0/PlantA/DCMD/EdgeNode1/PumpDevice"


def _hmac(tag, team, n):
    return hmac.new(CHALLENGE_SECRET.encode(), f"{tag}:{team}".encode(), hashlib.sha256).hexdigest()[:n]


def dynamic_flag(team):
    return f"flag{{mqtt_sparkplug_dcmd_injection_{_hmac('ICS-012', team, 12)}}}"


def attacker_ip(team):
    return f"10.90.0.{int(_hmac('ICS-012-ip', team, 4), 16) % 200 + 30}"


def _xor(d, k):
    return bytes(b ^ k[i % len(k)] for i, b in enumerate(d))


def build(team) -> list:
    rng = random.Random(int(_hmac("ICS-012-seed", team, 8), 16))
    ts = 1_700_000_000.0

    scada = pcap.TCPSession(LEGIT, BROKER_IP, PORT, client_port=41000)
    scada.handshake(ts)
    for _ in range(58):
        ts += rng.uniform(0.2, 1.0)
        metric = rng.choice(["Pump/Flow", "Pump/Pressure", "Tank/Level"])
        payload = mqtt.build_sparkplug_payload(metric, struct_body(rng.uniform(10, 90)))
        scada.client_msg(ts, mqtt.build_publish(DATA_TOPIC, payload))
    # 미끼: 정상 SCADA 의 DCMD(HMI 장치, 펌프 제어 아님)
    for _ in range(3):
        ts += rng.uniform(0.2, 0.8)
        payload = mqtt.build_sparkplug_payload(rng.choice(["Display/Refresh", "Alarm/Ack"]), b"\x01")
        scada.client_msg(ts, mqtt.build_publish("spBv1.0/PlantA/DCMD/EdgeNode1/HMIDevice", payload))

    # 사보타주: rogue 가 DCMD 토픽으로 펌프 액추에이터 명령 주입(body=토큰)
    rogue = pcap.TCPSession(attacker_ip(team), BROKER_IP, PORT, client_port=42000)
    t_atk = 1_700_000_000.0 + rng.uniform(15, 60)
    rogue.handshake(t_atk)
    token = _xor(dynamic_flag(team).encode(), attacker_ip(team).encode())
    payload = mqtt.build_sparkplug_payload("Pump/Control/Run", token)
    rogue.client_msg(t_atk + 0.05, mqtt.build_publish(DCMD_TOPIC, payload))

    records = scada.records + rogue.records
    records.sort(key=lambda r: r[0])
    return records


def struct_body(v: float) -> bytes:
    import struct
    return struct.pack("<f", v)


def main():
    team = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    out = os.path.join(os.path.dirname(__file__), "mqtt_sabotage.pcap")
    pcap.write_pcap(out, build(team))
    print(f"생성 완료: mqtt_sabotage.pcap (team={team}, attacker={attacker_ip(team)})")


if __name__ == "__main__":
    main()
