# ICS-004 — IEC 104 명령 주입 분석 (실 pcap 포렌식) 라이트업
- 분야: ics / 난이도: medium / MITRE ATT&CK for ICS: T0855

## 무엇이 달라졌나 (합성 JSON 로그 → 실 pcap)
`iec104_sabotage.pcap` — **진짜 IEC 60870-5-104 캡처**. Wireshark 가 포트 2404 를 IEC 104 로
디섹션한다. 프레임은 `shared/ics/iec104.py`(APCI/ASDU) + `shared/net/pcap.py`.

## 의도된 해법
1. Wireshark `104asdu` 필터. 2. 보호 차단기(CB, IOA=7)에 제어 ASDU(C_SC 등)를 정상 제어국
(10.40.0.3)이 아닌 출발지에서 찾는다 → 공격자 IP. 3. 명령 ASDU 정보요소(SCO 뒤 토큰)를
공격자 IP 로 반복 XOR → flag.

## 검증
`artifact_solve` 통과 + 빈제출 거부. tcpdump 로 pcap 구조 유효 확인. 팀별 HMAC 유니크.
