"""
ICS-005 배포 생성기 — 실 Profinet DCP 스푸핑 캡처(.pcap) 합성.
==============================================================
목업 JSON 로그가 아니라 **진짜 Profinet DCP 트래픽**(raw Ethernet, EtherType 0x8892)을 담은
pcap 을 만든다. Wireshark 가 PN-DCP 로 디섹션한다. DCP 프레임은 플랫폼 트윈과 동일한
`shared/ics/profinet.py` 실 인코더로 만든다.

시나리오: 정상 스테이션들의 DCP Ident 응답 사이에, 무단 MAC(rogue, 팀별)이 대상 스테이션
(plc-line-a)의 station_name 을 다른 IP 로 DCP-Set 하는 신원 스푸핑(MITM)이 숨어 있다. 그
Set 프레임에는 Type-of-Station 블록으로 토큰(= flag ⊕ 공격자 MAC)이 실려 있다. 분석: 대상
station_name 을 정상 MAC 이 아닌 출발지가 DCP-Set 한 프레임을 찾아 공격자 MAC 을 식별하고,
토큰 블록을 공격자 MAC 으로 반복 XOR 복호하면 flag.

팀별 rogue MAC·flag·타이밍이 HMAC 결정. 모든 값은 합성 더미(실장비/실호스트 무관).
"""
import hashlib
import hmac
import os
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))  # repo 루트(shared 임포트)

from shared.ics import profinet as pn
from shared.net import pcap

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요.")

LEGIT_MAC = "00:0e:cf:11:22:33"
TARGET_STATION = "plc-line-a"
ETHERTYPE_PN = 0x8892
FRAMEID_IDENT_RSP = b"\xfe\xfe"
FRAMEID_SET = b"\xfe\xfd"
DCP_MULTICAST = bytes.fromhex("010ecf000000")


def _hmac(tag, team, n):
    return hmac.new(CHALLENGE_SECRET.encode(), f"{tag}:{team}".encode(), hashlib.sha256).hexdigest()[:n]


def dynamic_flag(team):
    return f"flag{{profinet_dcp_spoof_{_hmac('ICS-005', team, 12)}}}"


def attacker_mac(team):
    h = _hmac("ICS-005-mac", team, 8)
    return "de:ad:" + ":".join(h[i:i + 2] for i in range(0, 8, 2))


def _mac_b(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", ""))


def _xor(d, k):
    return bytes(b ^ k[i % len(k)] for i, b in enumerate(d))


def _ident_response(name: str) -> bytes:
    block = pn.encode_block(pn.OPT_DEVICE, pn.SUB_DEV_NAMEOFSTATION, name.encode(), block_info=0)
    return FRAMEID_IDENT_RSP + pn.encode_dcp_frame(pn.SERVICE_IDENTIFY, pn.TYPE_RESPONSE, 1, [block])


def _spoof_set(name: str, token: bytes) -> bytes:
    name_block = pn.encode_block(pn.OPT_DEVICE, pn.SUB_DEV_NAMEOFSTATION, name.encode())
    token_block = pn.encode_block(pn.OPT_DEVICE, pn.SUB_DEV_VENDOR, token)
    return FRAMEID_SET + pn.encode_dcp_frame(pn.SERVICE_SET, pn.TYPE_REQUEST, 2, [name_block, token_block])


def build(team) -> list:
    rng = random.Random(int(_hmac("ICS-005-seed", team, 8), 16))
    ts = 1_700_000_000.0
    records = []
    stations = [("plc-line-a", LEGIT_MAC), ("hmi-a", "00:0e:cf:44:55:66"),
                ("io-dev-3", "00:0e:cf:77:88:99")]
    for _ in range(50):
        ts += rng.uniform(0.5, 2.0)
        name, mac = rng.choice(stations)
        frame = pcap.ethernet(_mac_b(mac), DCP_MULTICAST, ETHERTYPE_PN, _ident_response(name))
        records.append((ts, frame))

    # 스푸핑: rogue MAC 이 TARGET_STATION 을 DCP-Set (토큰 블록 포함)
    ts += rng.uniform(5, 30)
    token = _xor(dynamic_flag(team).encode(), attacker_mac(team).encode())
    rogue_frame = pcap.ethernet(_mac_b(attacker_mac(team)), _mac_b(LEGIT_MAC),
                                ETHERTYPE_PN, _spoof_set(TARGET_STATION, token))
    records.append((ts, rogue_frame))

    records.sort(key=lambda r: r[0])
    return records


def main():
    team = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    out = os.path.join(os.path.dirname(__file__), "profinet_dcp.pcap")
    pcap.write_pcap(out, build(team))
    print(f"생성 완료: profinet_dcp.pcap (team={team}, attacker_mac={attacker_mac(team)})")


if __name__ == "__main__":
    main()
