# ICS-003 — DNP3 무단 제어 분석 (실 pcap 포렌식) 라이트업

- 분야: ics / 난이도: medium / MITRE ATT&CK for ICS: T0855

## 무엇이 달라졌나 (합성 JSON 로그 → 실 pcap)
아티팩트가 `dnp3_sabotage.pcap` — **진짜 DNP3(IEEE 1815) 캡처**다. Wireshark 가 포트 20000 을
DNP3 로 디섹션한다. 프레임은 트윈과 동일한 `shared/ics/dnp3.py`(데이터링크 CRC 포함) +
`shared/net/pcap.py` 로 만든다.

## 의도된 해법
1. pcap 을 연다(Wireshark: `dnp3` 필터).
2. 보호 제어점(차단기 CB, index 7)에 대한 DIRECT_OPERATE(FC5)를 정상 마스터(10.30.0.4)가
   아닌 출발지에서 찾는다 = 무단 마스터 → 그 src IP 가 공격자.
3. 그 프레임의 g110 octet string 오브젝트(토큰)를 공격자 IP 로 반복 XOR → flag.

## 검증
- `artifact_solve`(생성→solve→grade_red PASS + 빈제출 거부), tcpdump 로 pcap 구조 유효 확인.
  팀별 HMAC 으로 공격자 IP·토큰·플래그 유니크.
