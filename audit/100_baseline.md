# 100 — v1.0 마감 기준선 실측 (Phase 0)

- 측정일: 2026-09-30
- 대상 리비전: `main` HEAD `9939453` (feat: CRY-020·PWN-022, PR #104)
- 작업트리: clean · origin/main 동기화 · open PR 0
- 방식: **실제 실행.** pytest·validate_challenges 로컬 실행 + gh 로 CI 결과 조회.
- 환경: WSL2 Ubuntu 22.04 · python3 3.10.12 · pytest 9.1.1 · RAM 11Gi(가용 ~4.6Gi) · 12 vCPU
- 메모리 제약(규칙 5): 전체 스택 미기동. 도커 검증은 Phase 1 이후 단일 서비스 묶음으로만.

---

## 0. 요약 판정

| 항목 | 실측값 | 근거 |
|---|---|---|
| 백엔드 테스트 | **738 passed / 6 skipped** (로컬, 65~79s) | `python3 -m pytest tests/` |
| 챌린지 검증 | **130 / 130 통과** | `bash scripts/validate_challenges.sh` |
| CI (ci.yml) 최신 main 실행 | **13잡 전부 success** | `gh run view 35344915181` |
| nightly loadtest / weekly saturation | success (2026-09-29 / 09-27) | `gh run list` |

기준선은 **green**. 단, 문서(README·CHANGELOG·태그)가 코드 실측과 어긋나 있음(§4).

---

## 1. Git / 릴리스 상태

- HEAD: `9939453` · `main`, `origin/main` 동기, 워킹트리 clean, open PR 0.
- **⚠️ `v1.0.0` 태그가 이미 존재하며 stale**:
  - 가리키는 커밋: `dc8f526` = PR #27 "docs 동기화"(2026-08-25).
  - 당시 근거: "70 챌린지 · 434 유닛 · CI 7/7". 현재 main은 그로부터 **77 커밋 앞**(130 챌린지·738 유닛·13잡).
  - `v1.0.0`은 main의 조상(ancestor)임 → 태그가 옛 상태에 박제됨.
  - **조치 필요(Phase 5, 승인 대상)**: 태그를 현재 HEAD로 옮길지(force) / 신규 버전으로 갈지 사용자 결정 필요. 규칙 6에 따라 임의 이동·강제푸시 금지.

---

## 2. 테스트 기준선

```
python3 -m pytest tests/ -q     → 738 passed, 6 skipped, 52 warnings (65~79s)
```
- **skip 6건**: `tests/attack_defense/test_postgres_ha.py` 전부 — `ATTACK_DEFENSE_TEST_POSTGRES_URL` 미설정(로컬 postgres 없음). CI unit 잡은 postgres 서비스로 기동해 통과. → 로컬 skip은 환경 문제이지 결함 아님.
- warnings 52건: JWT InsecureKeyLengthWarning(테스트용 짧은 키), pydantic field shadow(`register`) — 기능 무해, 정리 후보(POST_V1_BACKLOG).
- 수집 총계: 744 collected.

---

## 3. 챌린지 카탈로그 기준선

```
bash scripts/validate_challenges.sh
 → 검증 130  (아티팩트 42 / 탐지 14 / 서비스·스키마만 74)  ✅ 전체 통과
```

| 카테고리 | 수 |
|---|---|
| web | 24 |
| pwn | 23 |
| crypto | 21 |
| detection | 14 |
| ics | 13 |
| ai | 9 |
| forensics | 9 |
| network | 9 |
| reversing | 8 |
| **총합** | **130** |

- 서비스형 74종은 스키마만 검증(실배포 E2E는 별도). 아티팩트 42·탐지 14는 생성→solve/채점까지 CI에서 실검증.
- SIEM 탐지 규칙 YAML: 16개 파일 로드.

---

## 4. 문서 ↔ 실측 드리프트 (Phase 5에서 정정 대상)

| 위치 | 문서 주장 | 실측 |
|---|---|---|
| README:7 | "70개 CTF 챌린지" | **130** |
| README:772 | "챌린지 카탈로그 (112종)" | **130** |
| README:44 | "백엔드 687개 통과" | **738 passed / 6 skipped** |
| README:333 | "349 passed, 6 skipped" | (구식) |
| README:914,6 | 트윈 취약 서비스 "60종" | 재확인 필요(Phase 5) |
| CHANGELOG | `[Unreleased]` 유지 | 1.0.0 정리 미완 |
| `v1.0.0` 태그 | dc8f526(#27) | HEAD보다 77커밋 뒤 |

→ README 내부에서도 챌린지 수가 70/112로 불일치. Phase 5에서 실측값(130)으로 일원화.

---

## 5. CI 기준선

최신 `ci.yml` main 실행(run 35344915181, 커밋 9939453) — **13잡 전부 success**:
`unit · service-scope-drill · clean-install · challenges · dashboard · integration · secret-scan · supply-chain · command-platform · specialist-dashboards(siem/edr/blueportal/redportal)`.

스케줄 워크플로: Load Test(nightly) 2026-09-29 success · Saturation Test(weekly) 2026-09-27 success.

---

## 6. Phase 1(재감사) 대상 목록

audit/99_final.md 에서 현재 HEAD 재판정할 항목:
- **§1 Showstopper S-1 ~ S-11** (11건)
- **§2 2차 결함** (210~246행)
- **§6 UNVERIFIED** (378~400행, 10건 — 메모리상 종료됐다고 기록되나 재확인)

판정 라벨: FIXED(재현 실패 증거 필수) / PARTIAL / OPEN / UNVERIFIED.
산출물: `audit/101_reaudit.md`. Phase 1 직후 멈추고 승인 대기(규칙/보고형식).

---

## 7. 남은 위험 (기준선 시점)

1. 문서 드리프트가 "S-1 허위 보증" 정신에 위배 — 실측과 다른 수치가 README/태그에 남아 있음.
2. `v1.0.0` 태그 선점 — 릴리스 마감 시 충돌.
3. 로컬 메모리 4.6Gi — 도커 E2E는 단일 묶음씩만 가능(전체 스택 불가). Live Fire/A/D 리허설(Phase 3)은 서브셋 순차 기동 설계 필요.
4. 8h 소크·실HW·수동 접근성 감사는 이 환경에서 코드 완결 불가 → UNVERIFIED 유지 가능성.
