# ICS-012 — MQTT Sparkplug B 무단 액추에이터 명령 분석 - DCMD Injection 라이트업

- 분야: ics / 난이도: medium / MITRE: T0855, T0831

## 의도된 해법
1. `mqtt_traffic.jsonl` 파싱 → 판별자 부합 & 정상 출발지(10.90.0.5) 아님 = 무단 프레임.
2. 그 src가 공격자 IP. note(base64)를 공격자 IP로 XOR → flag.

## 검증
- C-QA artifact_solve: 생성→solve→grade + 빈제출 거부. 팀별 유니크.
