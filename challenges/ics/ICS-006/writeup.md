# ICS-006 — IEC 61850 GOOSE 위조 분석 라이트업

- 분야: ics / 난이도: hard / MITRE: T0832(Manipulation of View), T0855

## 의도된 해법
1. `goose_messages.jsonl` 파싱 → gocbRef=보호 트립 gcb 이고 dataset에 "true"(CB_Trip)이며
   src_mac≠정상 IED(00:21:c1:aa:bb:cc)인 레코드 = 스푸핑된 트립 GOOSE(비정상 stNum 급증 동반).
2. 그 src_mac이 공격자 MAC. note(base64)를 공격자 MAC으로 XOR → `flag{iec61850_goose_spoof_<hmac12>}`.

## 검증
- C-QA `run_all.py --challenge ICS-006`(artifact_solve): 생성→solve→grade + 빈제출 거부. 팀별 유니크.
