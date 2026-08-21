# ICS-005 — Profinet DCP 스푸핑 분석 (실 pcap 포렌식) 라이트업

- 분야: ics / 난이도: medium / MITRE ATT&CK for ICS: T0842, T0830

## 무엇이 달라졌나 (합성 JSON 로그 → 실 pcap)
아티팩트가 `profinet_dcp.pcap` — **진짜 Profinet DCP 캡처**(raw Ethernet, EtherType 0x8892)다.
Wireshark 가 PN-DCP 로 디섹션한다. 프레임은 트윈과 동일한 `shared/ics/profinet.py` +
`shared/net/pcap.py`(L2 프레이밍)로 만든다.

## 의도된 해법
1. pcap 을 연다(Wireshark: `pn_dcp` 필터).
2. 대상 스테이션(plc-line-a)을 **DCP-Set** 하는 프레임을 정상 MAC(00:0e:cf:11:22:33)이 아닌
   출발지에서 찾는다 = 신원 스푸핑(MITM) → 그 src MAC 이 공격자.
3. 그 Set 프레임의 Type-of-Station 블록(토큰)을 공격자 MAC 으로 반복 XOR → flag.

## 검증
- `artifact_solve`(생성→solve→grade_red PASS + 빈제출 거부). 팀별 HMAC 으로 MAC·토큰·플래그
  유니크. (재저작 시 attacker_mac 을 6옥텟로 정정 — 원본은 5옥텟 malformed.)
