# ICS-002 — Modbus 사보타주 분석 (실 pcap 포렌식) 라이트업

- 분야: ics / 난이도: medium / MITRE ATT&CK for ICS: T0836, T0855

## 무엇이 달라졌나 (합성 JSON 로그 → 실 pcap)
아티팩트가 단순 JSON 로그가 아니라 **진짜 Modbus/TCP 캡처**(`modbus_sabotage.pcap`)다.
Wireshark·tcpdump 가 포트 502 를 Modbus 로 그대로 디섹션한다. 프레임은 플랫폼 트윈과 동일한
`shared/ics/modbus.py`(실 PDU) + `shared/net/pcap.py`(L2~L4 프레이밍) 로 만든다 — 실제 SOC
분석과 같은 워크플로.

## 의도된 해법
1. pcap 을 연다(Wireshark: `modbus` 필터, 또는 `tshark -r ... -Y modbus`).
2. 안전 레지스터(40001 = **프로토콜 주소 0**)에 대한 write(FC5/6/16)를 찾는다. 정상 HMI
   (10.20.0.5)가 아닌 출발지에서 온 **FC16 다중 쓰기**가 사보타주 = 무단 마스터.
3. 그 패킷의 src IP 가 공격자 IP. FC16 페이로드(쓰여진 레지스터 바이트)를 공격자 IP 로
   반복 XOR → `flag{modbus_sabotage_<hmac12>}`.

## 실 도구 예시
```bash
tshark -r modbus_sabotage.pcap -Y 'modbus.func_code == 16'   # 안전영역 무단 쓰기 식별
```
`solution/exploit.py` 는 `shared/net/pcap.py`(reader) + `shared/ics/modbus.py`(parse_pdu)
로 동일 분석을 자동화한다.

## 검증
- 스키마 + `artifact_solve`(생성→solve→grade_red PASS + 빈제출 거부). 팀별 HMAC 으로
  공격자 IP·토큰·플래그 유니크. pcap 은 tcpdump 로 구조 유효성 확인.
