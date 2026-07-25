# DET-012 방어 노트 — MQTT Sparkplug B 무단 액추에이터 DCMD 탐지

## 핵심
message_type=DCMD AND metric~Pump/Control 동시 매칭. 단일조건(DCMD만/metric~Pump/Control만)은 정상 DCMD/텔레메트리에 오탐 → AND 결합 필수.
