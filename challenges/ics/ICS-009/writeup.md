# ICS-009 — Foundation Fieldbus 블록 MODE 조작 분석 라이트업

- 분야: ics / 난이도: hard / MITRE: T0836, T0855, T0831

## 의도된 해법
1. `ff_h1_traffic.jsonl` 파싱 → block=FIC-201(안전 PID)이고 param=MODE_BLK, op=write, value=OOS이며
   src_addr∉{0x10 LAS, 0x11 DCS}인 프레임 = 무단 호스트.
2. 그 src_addr가 공격자 FF 링크주소. note(base64)를 공격자 주소로 XOR
   → `flag{ff_mode_blk_oos_sabotage_<hmac12>}`.

## 배경
- MODE_BLK.TARGET=O/S(Out of Service)는 FF 함수블록을 정지시켜 PID 제어 루프를 사실상 무력화
  (계측/제어 정지). 안전 관련 블록에 대한 원격 O/S 전환은 전형적 프로세스 사보타주(T0831 Manipulation).

## 함정
- 정상 DCS(0x11)도 SP를 write 하지만 param(MODE_BLK 아님)과 주소로 걸러진다.

## 검증
- C-QA `run_all.py --challenge ICS-009`(artifact_solve): 생성→solve→grade + 빈제출 거부. 팀별 유니크.
