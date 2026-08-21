# ICS-011 — S7comm 안전 DB 무단 쓰기 분석 (실 pcap 포렌식) 라이트업

- 분야: ics / 난이도: hard / MITRE ATT&CK for ICS: T0836, T0855

## 무엇이 달라졌나 (합성 JSON 로그 → 실 pcap)
아티팩트가 `s7_sabotage.pcap` — **진짜 S7comm(TPKT/COTP/S7) 캡처**다. Wireshark 가 포트 102 를
S7COMM 으로 디섹션한다. 프레임은 트윈과 동일한 `shared/ics/s7comm.py` + `shared/net/pcap.py`
로 만든다(COTP CR/CC + S7 Setup 세션 확립 포함).

## 의도된 해법
1. pcap 을 연다(Wireshark: `s7comm` 필터).
2. 안전 데이터블록(DB 62)에 WRITE_VAR(func 0x05)를 정상 엔지니어링 스테이션(10.85.0.5)이
   아닌 출발지에서 찾는다 → 그 src IP 가 공격자.
3. 그 WRITE_VAR 의 데이터 바이트(토큰)를 공격자 IP 로 반복 XOR → flag.

## 검증
- `artifact_solve`(생성→solve→grade_red PASS + 빈제출 거부). 팀별 HMAC 유니크.
