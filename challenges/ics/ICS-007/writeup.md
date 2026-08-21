# ICS-007 — HART 명령 주입 분석 (실 pcap 포렌식) 라이트업

- 분야: ics / 난이도: medium / MITRE ATT&CK for ICS: T0836, T0855

## 무엇이 달라졌나 (합성 JSON 로그 → 실 pcap)
아티팩트가 `hart_sabotage.pcap` — **진짜 HART-IP 캡처**다. Wireshark 가 포트 5094 를 HART-IP
로 디섹션한다. 프레임은 트윈과 동일한 `shared/ics/hart.py`(HART-IP 헤더 + short-frame PDU +
XOR 체크섬) + `shared/net/pcap.py` 로 만든다.

## 의도된 해법
1. pcap 을 연다(Wireshark: `hart_ip` 필터).
2. 안전 트랜스미터(PT-101 = polling address 1)에 write 명령(cmd 34/35/45/46)을 정상 AMS
   (10.60.0.5)가 아닌 출발지에서 찾는다 → 그 src IP 가 공격자.
3. 그 cmd 35 프레임의 HART 데이터 바이트(토큰)를 공격자 IP 로 반복 XOR → flag.

## 검증
- `artifact_solve`(생성→solve→grade_red PASS + 빈제출 거부). 팀별 HMAC 유니크.
