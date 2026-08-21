# ICS-008 — BACnet 무단 WriteProperty 분석 (실 pcap 포렌식) 라이트업
- 분야: ics / 난이도: medium / MITRE ATT&CK for ICS: T0855, T0836

## 무엇이 달라졌나 (합성 JSON 로그 → 실 pcap)
`bacnet_sabotage.pcap` — **진짜 BACnet/IP 캡처**. Wireshark 가 UDP 47808 을 BACnet 으로
디섹션한다. 프레임은 `shared/ics/bacnet.py`(BVLC/NPDU/APDU) + `shared/net/pcap.py`.

## 의도된 해법
1. Wireshark `bacnet` 필터. 2. 냉방 setpoint(analog-output)에 WriteProperty(우선순위 8)를
정상 BMS(10.70.0.10)가 아닌 출발지에서 찾는다 → 공격자 IP. 3. WriteProperty 값(OctetString,
토큰)을 공격자 IP 로 반복 XOR → flag.

## 검증
`artifact_solve` 통과 + 빈제출 거부. 팀별 HMAC 유니크.
