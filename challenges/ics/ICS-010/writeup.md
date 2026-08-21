# ICS-010 — EtherNet/IP CIP 무단 제어 분석 (실 pcap 포렌식) 라이트업
- 분야: ics / 난이도: hard / MITRE ATT&CK for ICS: T0836, T0855, T0831

## 무엇이 달라졌나 (합성 JSON 로그 → 실 pcap)
`enip_sabotage.pcap` — **진짜 EtherNet/IP + CIP 캡처**. Wireshark 가 포트 44818 을 ENIP/CIP 로
디섹션한다. 프레임은 `shared/ics/enip.py`(ENIP 캡슐화+CIP) + `shared/net/pcap.py`.

## 의도된 해법
1. Wireshark `cip` 필터. 2. 안전 Assembly(class 0x04, instance 101)에 SetAttributeSingle(0x10)을
정상 스캐너(10.80.0.5)가 아닌 출발지에서 찾는다 → 공격자 IP. 3. CIP 요청 데이터(토큰)를
공격자 IP 로 반복 XOR → flag.

## 검증
`artifact_solve` 통과 + 빈제출 거부. 팀별 HMAC 유니크.
