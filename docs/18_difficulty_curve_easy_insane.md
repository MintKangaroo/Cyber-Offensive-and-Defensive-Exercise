# 난이도 곡선 채우기 — 분야별 easy / insane 문제

> 12~16번에서 각 분야 medium~hard를 확보했다. 여기서 각 분야의 **easy(도입)**와
> **insane(정교)** 문제를 추가해 easy→insane 곡선을 완성한다. 모두 11번 표준 구조(요약).

---

## WEB

### WEB-000 (easy) — 노출된 디버그 설정
```yaml
id: "WEB-000"; category: web; difficulty: easy; points: {red: 50, blue: 50}
asset: ground_station; mitre: [T1592]
red_task: { goal: "/api/debug/config 접근해 노출된 JWT 시크릿 확보", flag_format: "flag{...}" }
blue_task: { goal: "디버그 라우트 제거 패치 + 접근 탐지룰", success_criteria: "safe_probe 404 + 알림" }
scoring: { red_verify: flag_match, blue_verify: [safe_probe, alert] }
```
도입용. GS-005 그대로 활용. "정찰=첫 단추" 개념 학습.

### WEB-009 (insane) — 다단계 WAF 우회 + 블라인드 추출
```yaml
id: "WEB-009"; category: web; difficulty: insane; points: {red: 400, blue: 350}
asset: ground_station; mitre: [T1190]
red_task:
  goal: "WAF가 켜진 상태에서 인코딩/청크/파라미터오염 조합으로 우회, 블라인드 SQLi로 시크릿 추출"
  flag_format: "flag{...}"
  hints: [{cost:50,text:"단일 우회론 안 된다. 여러 기법을 체이닝하라."}]
blue_task:
  goal: "우회를 막는 정교한 룰 재작성(정탐 유지, 오탐 최소)"
  success_criteria: "우회 페이로드 차단 & 정상요청 오탐 0 & 블라인드 추출 방지"
scoring: { red_verify: flag_match, blue_verify: [block, alert] }
safety: { profile: standard }
```
Red↔Blue 정면대결(룰 vs 우회). 비의도 방지: 여러 우회 경로를 의도 해법으로 등록해 C-QA가 검증.

---

## FORENSICS

### FOR-000 (easy) — 평문 자격증명 카빙
```yaml
id: "FOR-000"; category: forensics; difficulty: easy; points: {red: 50, blue: 30}
mitre: [T1552.001]
red_task: { goal: "제공된 설정 백업에서 평문 자격증명 찾기", submit_fields: [service_account, password] }
blue_task: { goal: "평문 저장의 위험 서술 + 볼트 이관 방식 제시" }
artifacts: [ "backup_config.txt" ]
```
strings/grep 수준 도입. DN-003과 연계.

### FOR-009 (insane) — 안티포렌식 + 다단계 복원
```yaml
id: "FOR-009"; category: forensics; difficulty: insane; points: {red: 400, blue: 200}
mitre: [T1070]
red_task:
  goal: "타임스탬프 조작·부분삭제된 이미지에서 원 사건 복원 → 은닉된 스테가노 플래그까지 3단 추적"
  submit_fields: [timeline_tamper_evidence, hidden_channel, final_flag]
  hints: [{cost:60,text:"$MFT와 로그 타임스탬프 불일치를 대조하라."}]
blue_task: { goal: "이런 안티포렌식을 탐지하는 무결성 모니터링 설계(서술+룰)" }
artifacts: [ "tampered_image.dd" ]
safety: { profile: standard }
```
결정론 생성기로 조작 흔적을 정확히 심어 채점 가능하게.

---

## DETECTION

### DET-000 (easy) — 첫 브루트포스 룰
```yaml
id: "DET-000"; category: detection; difficulty: easy; points: {red: 0, blue: 60}
mitre: [T1110]
blue_task:
  goal: "동일 src의 로그인 401 연속을 잡는 단순 임계 룰 작성"
  success_criteria: "공격셋 알림 + 정상셋 오탐0"
artifacts: [ "bruteforce.jsonl", "normal.jsonl" ]
```
Sigma 첫 작성. 임계 룰 개념 도입.

### DET-009 (insane) — APT 저속 킬체인 헌팅
```yaml
id: "DET-009"; category: detection; difficulty: insane; points: {red: 0, blue: 400}
mitre: [T1046, T1071, T1041]
blue_task:
  goal: "수일에 걸친 저속(low-and-slow) 공격을 대량 노이즈 속에서 헌팅, 시퀀스+주기성+볼륨 상관"
  success_criteria: "은닉된 킬체인 발견 + ATT&CK 매핑 리포트 + 오탐 최소"
  points_breakdown: { find_chain: 200, attack_mapping: 100, low_fp: 100 }
artifacts: [ "week_long_logs.jsonl (대용량, 노이즈 90%+)" ]
```
위협헌팅 최고난도. 노이즈 생성기(06)로 현실적 배경 생성. 저속 공격이라 단순 임계론 안 잡힘.

---

## AI

### AI-000 (easy) — 특징공간 회피 (개념)
```yaml
id: "AI-000"; category: ai; difficulty: easy; points: {red: 60, blue: 40}
mitre: [T1027]
red_task: { goal: "제약 없는 feature-space에서 탐지기 오분류 유도(개념 확인)", flag_on_success: "flag{feature_space_evasion}" }
blue_task: { goal: "왜 feature-space 회피가 비현실적인지 서술 + 입력검증 추가" }
safety: { profile: hardened }
```
AI-002(문제공간)의 도입판. "특징만 바꾸면 쉽지만 비현실적"을 먼저 체험.

### AI-009 (insane) — 방어된 IDS에 대한 전이 회피
```yaml
id: "AI-009"; category: ai; difficulty: insane; points: {red: 400, blue: 400}
mitre: [T1027]
red_task:
  goal: "adversarial training으로 방어된 IDS/멀웨어 분류기에, 대리모델 전이(transferability)로 회피 달성"
  submit_fields: [evasive_sample, transfer_method]
  hints: [{cost:70,text:"직접 공격이 막히면 대리모델을 학습해 전이하라."}]
blue_task:
  goal: "전이 회피까지 견디는 앙상블/탐지 방어"
  success_criteria: "전이 샘플 재탐지 + 원 정확도 유지 + 앙상블 다양성 확보"
scoring: { red_verify: "detector_query + constraint_check", blue_verify: holdout_eval }
safety: { profile: hardened; notes: "합성 데이터/모델. 강격리." }
```
적대적 견고성 공방의 정점. 04 점수연결로 회피/방어 실시간 채점. constraint_check 필수(비의도 차단).

---

## REVERSING

### REV-000 (easy) — 하드코딩 비밀번호
```yaml
id: "REV-000"; category: reversing; difficulty: easy; points: {red: 50, blue: 30}
mitre: [T1552.001]
red_task: { goal: "간단한 크랙미에서 하드코딩된 비밀번호/플래그 찾기(strings/디스어셈)", flag_format: "flag{...}" }
blue_task: { goal: "하드코딩 위험 설명 + 서버측 검증으로 전환" }
artifacts: [ "crackme_easy (ELF)" ]
```
strings → 기초 디스어셈 도입.

### REV-009 (insane) — 커스텀 VM 난독화
```yaml
id: "REV-009"; category: reversing; difficulty: insane; points: {red: 450, blue: 150}
mitre: [T1027.007]
red_task:
  goal: "커스텀 바이트코드 VM으로 난독화된 검증 로직 리버싱 → VM 명령셋 복원 → 플래그 도출"
  flag_format: "flag{...}"
  hints: [{cost:80,text:"핸들러 테이블을 찾아 VM opcode 의미를 매핑하라."}]
blue_task: { goal: "VM 난독화의 한계와 정당한 보호(서버검증/TPM) 논의" }
artifacts: [ "vm_crackme (ELF)" ]
safety: { profile: hardened }
```
리버싱 최고난도. 결정론 빌드로 팀별 플래그만 교체.

---

## NETWORK / OT

### NET-000 (easy) — 평문 프로토콜 스니핑
```yaml
id: "NET-000"; category: network; difficulty: easy; points: {red: 50, blue: 30}
mitre: [T1040]
red_task: { goal: "제공 pcap에서 평문 텔넷/HTTP 자격증명 추출", submit_fields: [username, password] }
blue_task: { goal: "평문 프로토콜 위험 + 암호화 전환 제안" }
artifacts: [ "plaintext_capture.pcap" ]
```
Wireshark 기초 도입.

### NET-009 (insane) — OT 다단계 사보타주
```yaml
id: "NET-009"; category: network; difficulty: insane; points: {red: 450, blue: 450}
asset: power_plant; mitre: [T0812, T0836, T0800]
red_task:
  goal: "IT망 침투 → OT 경계 우회 → Modbus/S7 조작으로 세이프티 무력화 + 물리 임계 초과(시뮬)까지 완주"
  flag_on_success: "flag{ot_sabotage_complete}"
  hints: [{cost:80,text:"IT→OT 피벗 지점을 찾고, 프로토콜 게이트웨이를 노려라."}]
blue_task:
  goal: "IT/OT 세그멘테이션 + OT 이상탐지 + 2인승인으로 전 단계 차단"
  success_criteria: "각 단계 차단 지점 확보 + Zeek OT 로그 탐지 + 세이프티 인터록 보호"
  points_breakdown: { it_ot_segmentation: 150, ot_detection: 150, safety_protection: 150 }
scoring: { red_verify: event, blue_verify: [block, alert] }
safety: { profile: hardened; notes: "OT 시뮬레이터 강격리. 실장비 미연결. 물리효과는 시뮬값." }
```
IT→OT 전체 킬체인. 05 시나리오 as-code로 다단계 엮음. 최고 배점.

---

## 난이도 곡선 완성 현황

| 분야 | easy | medium | hard | insane |
|---|---|---|---|---|
| Web | WEB-000 | WEB-002 | WEB-004 | WEB-009 |
| Forensics | FOR-000 | FOR-002, FOR-003 | — | FOR-009 |
| Detection | DET-000 | DET-002 | DET-004 | DET-009 |
| AI | AI-000 | AI-002 | AI-005 | AI-009 |
| Reversing | REV-000 | — | REV-003 | REV-009 |
| Network/OT | NET-000 | NET-002, NET-003 | — | NET-009 |

각 분야 easy~insane 확보. C1~C6이 빈 칸(일부 medium/hard)을 이 템플릿으로 채워 분야별 6~8문제로.

---

## insane 티어 구현 완료 (2026-07-14) — 6종 전부 C-QA PASS 실검증

위 설계를 **실제 실행/채점 가능한 형태**로 구현했다. 무거운 의존성(ML 프레임워크)·초대형
데이터·실장비가 필요한 일부 설계는 이 환경에서 결정론적으로 검증 가능한 등가물로 조정하되
**주제와 난이도 곡선은 유지**했다. 배점은 실제 저장소 스케일(hard REV-003≈140, WEB-005≈250)에
맞춰 하향 조정.

| ID | 구현 요지 | 검증 게이트 | 배점(red/blue) | C-QA |
|---|---|---|---|---|
| REV-009 | 핸들러테이블 순열 + LCG 키스트림 + 8-op 스택 VM 3중 난독화 바이트코드 | artifact_solve | 300 / 0 | ✅ PASS |
| FOR-009 | 타임스톰프(저널>MFT 모순) → 슬랙 은닉채널(base64) → 반복키 XOR 복호 3단 | artifact_solve | 300 / 0 | ✅ PASS |
| NET-009 | Modbus 트레이스: 미인가 쓰기(rogue) → 커버트 레지스터 → 하위바이트 base64 복원 | artifact_solve | 300 / 0 | ✅ PASS |
| AI-009 | 로지스틱 IDS 로그: 모델 재평가로 최소 L0 전이회피 쿼리 식별 → 섭동인덱스 키 XOR 복호 (ML 프레임워크 불요) | artifact_solve | 300 / 0 | ✅ PASS |
| DET-009 | APT low-and-slow 비콘(1800초, 노이즈 다수) periodicity 헌팅: window 확장+관측수/지터 튜닝+다중 allowlist | detection_solve (SIEM 엔진) | 0 / 200 | ✅ PASS |
| WEB-009 | 문자 블랙리스트 WAF 우회(`/**/`·`>`·무따옴표 함수) + 블라인드 불리언 SQLi 이진탐색 추출 | full docker (deploy/solve/blank/determinism/teardown) + blue patch | 300 / 150 | ✅ PASS |

- 모든 아티팩트/서비스는 팀별 HMAC(또는 정적 CHALLENGE_SECRET) 결정론 생성 → **빈 제출 거부** 및
  (아티팩트형) **팀별 유니크성** 실측 확인. WEB-009는 재배포 후 flag 일관성(determinism) 및
  패치판(PATCH_WEB_009=true)에서 우회 페이로드 400 거부 + 익스플로잇 차단까지 실검증.
- 설계 대비 조정: AI-009는 adversarial-training 실모델 대신 선형모델 로그 분석으로, NET-009는
  실 IT→OT 피벗 대신 Modbus 트레이스 재구성으로 등가 구현(오프라인 결정론 채점 가능).
  난이도 표의 insane 칸(WEB/FOR/DET/AI/REV/NET-009)은 이로써 전부 **구현·검증 완료**.
