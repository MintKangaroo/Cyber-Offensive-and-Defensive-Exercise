# ICS-009 — Foundation Fieldbus MODE 조작 분석 (실 pcap 포렌식) 라이트업
- 분야: ics / 난이도: hard / MITRE ATT&CK for ICS: T0836, T0855, T0831

## 무엇이 달라졌나 (합성 JSON 로그 → 실 FF-H1 DLPDU pcap)
`ff_h1_sabotage.pcap` — **실 FF-H1 DLPDU** 바이트. FF-H1 은 시리얼 필드버스라 IP 가 아니어서
사설 EtherType(0x88FF)로 합성 캡슐화(DLPDU 구조는 실제). `shared/ics/ff_h1.py`.
정직한 경계: Wireshark 네이티브 FF-H1 디섹션은 표준이 아니므로 커스텀 파서(exploit)로 분석.

## 의도된 해법
1. 안전 PID 블록(FIC-201)의 MODE_BLK 를 O/S(OOS)로 write 한 DLPDU 를 정상 노드(0x10/0x11)가
아닌 출발지에서 찾는다 → 공격자 노드주소. 2. DLSDU 토큰을 공격자 주소로 반복 XOR → flag.

## 검증
`artifact_solve` 통과 + 빈제출 거부. 팀별 HMAC 유니크.
