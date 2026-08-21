"""
ICS-006 배포 생성기 — 실 IEC 61850 GOOSE 위조 캡처(.pcap) 합성.
================================================================
목업 JSON 로그가 아니라 **진짜 GOOSE 트래픽**(raw Ethernet, EtherType 0x88B8)을 담은 pcap 을
만든다. Wireshark 가 GOOSE 로 디섹션한다. 프레임은 `shared/ics/goose.py` 실 인코더(BER)로 만든다.

시나리오: 정상 보호 IED(00:21:c1:aa:bb:cc)의 주기적 GOOSE(stNum 유지, CB_Trip=false) 사이에,
무단 MAC(rogue, 팀별)이 같은 gocbRef 로 높은 stNum 의 위조 트립 GOOSE(CB_Trip=true)를 주입한
사보타주가 숨어 있다. 그 위조 GOOSE 의 allData 옥텟열에 토큰(= flag ⊕ 공격자 MAC)이 실려 있다.
분석: 트립 gocbRef 로 CB_Trip=true 를 낸 정상 아닌 MAC 을 찾아 공격자 MAC 을 식별하고, 옥텟열을
공격자 MAC 으로 반복 XOR 복호하면 flag.

팀별 rogue MAC·flag·타이밍이 HMAC 결정. 모든 값은 합성 더미(실장비/실호스트 무관).
"""
import hashlib
import hmac
import os
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))  # repo 루트(shared 임포트)

from shared.ics import goose
from shared.net import pcap

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요.")

LEGIT_IED_MAC = "00:21:c1:aa:bb:cc"
TRIP_GCB = "IED1/LLN0$GO$gcbTrip"
DATASET = "IED1/LLN0$CB_Trip"
GOOSE_MULTICAST = bytes.fromhex("010ccd010000")


def _hmac(tag, team, n):
    return hmac.new(CHALLENGE_SECRET.encode(), f"{tag}:{team}".encode(), hashlib.sha256).hexdigest()[:n]


def dynamic_flag(team):
    return f"flag{{iec61850_goose_spoof_{_hmac('ICS-006', team, 12)}}}"


def attacker_mac(team):
    h = _hmac("ICS-006-mac", team, 8)
    return "de:ad:" + ":".join(h[i:i + 2] for i in range(0, 8, 2))


def _mac_b(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", ""))


def _xor(d, k):
    return bytes(b ^ k[i % len(k)] for i, b in enumerate(d))


def build(team) -> list:
    rng = random.Random(int(_hmac("ICS-006-seed", team, 8), 16))
    ts = 1_700_000_000.0
    records = []
    st = 1
    sq = 100
    for _ in range(50):
        ts += rng.uniform(0.2, 1.0)
        sq += 1
        payload = goose.build_goose(TRIP_GCB, DATASET, st_num=st, sq_num=sq, trip=False)
        records.append((ts, pcap.ethernet(_mac_b(LEGIT_IED_MAC), GOOSE_MULTICAST,
                                          goose.GOOSE_ETHERTYPE, payload)))
    # 스푸핑: rogue MAC 이 높은 stNum 으로 위조 트립 GOOSE 주입(옥텟열 = 토큰)
    ts += rng.uniform(1, 5)
    token = _xor(dynamic_flag(team).encode(), attacker_mac(team).encode())
    payload = goose.build_goose(TRIP_GCB, DATASET, st_num=st + 5000, sq_num=0,
                                trip=True, token=token)
    records.append((ts, pcap.ethernet(_mac_b(attacker_mac(team)), GOOSE_MULTICAST,
                                      goose.GOOSE_ETHERTYPE, payload)))

    records.sort(key=lambda r: r[0])
    return records


def main():
    team = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    out = os.path.join(os.path.dirname(__file__), "goose_messages.pcap")
    pcap.write_pcap(out, build(team))
    print(f"생성 완료: goose_messages.pcap (team={team}, attacker_mac={attacker_mac(team)})")


if __name__ == "__main__":
    main()
