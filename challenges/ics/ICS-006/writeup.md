# ICS-006 — IEC 61850 GOOSE 위조 분석 (실 pcap 포렌식) 라이트업
- 분야: ics / 난이도: hard / MITRE ATT&CK for ICS: T0832, T0855

## 무엇이 달라졌나 (합성 JSON 로그 → 실 pcap)
`goose_messages.pcap` — **진짜 GOOSE 캡처**(raw Ethernet 0x88B8). Wireshark 가 GOOSE 로
디섹션한다. 프레임은 `shared/ics/goose.py`(BER) + `shared/net/pcap.py`(L2).

## 의도된 해법
1. Wireshark `goose` 필터. 2. 트립 gocbRef(IED1/LLN0$GO$gcbTrip)로 CB_Trip=true 를 낸 프레임을
정상 IED MAC(00:21:c1:aa:bb:cc)이 아닌 출발지(높은 stNum 점프)에서 찾는다 → 공격자 MAC.
3. allData 옥텟열(토큰)을 공격자 MAC 으로 반복 XOR → flag.

## 검증
`artifact_solve` 통과 + 빈제출 거부. 팀별 HMAC 유니크. (재저작 시 attacker_mac 6옥텟 정정.)
