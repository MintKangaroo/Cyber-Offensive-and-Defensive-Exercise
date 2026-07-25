# DET-010 방어 노트 — EtherNet/IP CIP 안전 어셈블리 무단 SetAttribute 탐지

## 핵심
cip_service=16(SetAttributeSingle) AND cip_class=4 AND cip_instance=101 동시 매칭. 단일조건(service=16만/instance=101만/class=4만)은 정상 write/read에 오탐 → AND 결합 필수.
