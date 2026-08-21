# ICS-012 — MQTT Sparkplug B 무단 명령 분석 (실 pcap 포렌식) 라이트업
- 분야: ics / 난이도: medium / MITRE ATT&CK for ICS: T0855, T0831

## 무엇이 달라졌나 (합성 JSON 로그 → 실 pcap)
`mqtt_sabotage.pcap` — **진짜 MQTT 캡처**(Sparkplug B). Wireshark 가 포트 1883 을 MQTT 로
디섹션한다(토픽·PUBLISH). 프레임은 `shared/ics/mqtt_sparkplug.py` + `shared/net/pcap.py`.

## 의도된 해법
1. Wireshark `mqtt` 필터. 2. DCMD 토픽(spBv1.0/…/DCMD/…)으로 펌프 액추에이터 명령
(Pump/Control/Run)을 정상 SCADA(10.90.0.5)가 아닌 출발지에서 찾는다 → 공격자 IP.
3. Sparkplug body(토큰)를 공격자 IP 로 반복 XOR → flag.

## 검증
`artifact_solve` 통과 + 빈제출 거부. 팀별 HMAC 유니크.
