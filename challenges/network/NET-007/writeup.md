# NET-007 — 다중 홉 피벗 체인 상관 추적 라이트업

## 개요
- 분야: network / 난이도: hard / MITRE: T1090.003(Internal Proxy / Multi-hop pivot)
- 아티팩트: `netflow.jsonl` — {ts, src, dst, dport, bytes, note} 넷플로우 레코드.

## 의도된 해법
1. **진입 시드**: src가 외부 대역(203.0.113.x)인 플로우를 진입점으로 잡는다.
2. **홉 그래프 상관 확장**: 현재 홉의 dst를 src로 갖고, 시각이 수십 ms 뒤이며(0<Δt<0.2s),
   바이트가 거의 보존된(±80) 다음 플로우를 그리디로 이어 붙여 DC(10.4.0.10) 도달까지 체인을 복원.
   → 시각이 벌어진 미끼/무관 트래픽은 상관 조건에서 탈락.
3. **토큰 복호**: 최종 홉(dst=DC) note(base64)를 디코드 → 진입 IP로 반복 XOR → `flag{pivot_chain_<hmac12>}`.

## 왜 hard인가
- 바이트/포트 필터만으로는 미끼와 구분 불가 — **시간·토폴로지 상관**으로 체인을 그려야 한다.
- 체인 복원 후에도 진입 IP를 키로 한 XOR 복호가 필요.

## 검증
- C-QA `run_all.py --challenge NET-007`(artifact_solve): 생성 → solve(체인복원+복호) → grade_red PASS +
  빈 제출 거부. 팀별 HMAC으로 진입 IP/경로/토큰/플래그가 유니크(같은 팀은 재생성에도 동일).
