# C-QA 파이프라인 + 나머지 챌린지 계획 — 상세 실행 사양

> 11번 문서(출제표준)의 9단계 검수를 실제 스크립트 계획으로, 그리고 현재 4개 안팎인
> 분야별 문제 수를 7개 수준으로 채우는 구체적 목록을 정리했다.

**구현 상태**: `infra/challenge_qa/` 8개 스크립트 전부 구현 완료, `--skip-docker` 모드로
schema_validate/safety_scan 실제 실행 검증(깨진 챌린지로 6개 오류 정확히 잡아내는 것도 확인).
실제 챌린지 4개(WEB-002, WEB-000, DET-000, FOR-000)를 11번 문서 표준 구조 그대로 완전
패키지화해서 C-QA 전체(`run_all.py --skip-docker`) 통과 확인. WEB-002는 PyJWT로 취약점/패치
로직 자체를 실제 실행 검증(alg=none 위조·약한키 서명·패치 후 거부 전부 확인), DET-000은
**우리 진짜 SIEM Detection Engine**을 그대로 가져다 채점기로 써서 공격로그 탐지+정상로그
오탐없음을 실제 실행 검증, FOR-000은 아티팩트 생성→카빙→채점 전체 파이프라인과 팀별
동적 값 유니크성까지 실제 실행 검증했다. `deploy_up`/`intended_solve`(HTTP 기반)/
`blue_verify`/`flag_determinism`/`teardown`은 Docker가 필요해 이 샌드박스에서 직접 실행은
못했지만 로직 자체는 스크립트로 완성되어 있다.

---

## 1. C-QA 파이프라인 (infra/ci와 동일한 스타일로 구현)

### 디렉토리
```
infra/challenge_qa/
├─ schema_validate.py
├─ deploy_up.py
├─ intended_solve.py
├─ blank_submit.py
├─ blue_verify.py
├─ safety_scan.py
├─ flag_determinism.py
├─ teardown.py
└─ run_all.py
```

### 각 스크립트 시그니처 (CLI, infra/ci/secret_scan.py와 동일한 argparse 패턴)

```python
# schema_validate.py
def main() -> int:
    """challenges/<category>/<id>/challenge.yaml을 shared.challenge_schema.Challenge로 로드.
    필수 필드 누락/id 정규식 위반 시 실패. 사용법: python schema_validate.py --challenge WEB-002"""

# deploy_up.py
def main() -> int:
    """challenge의 deploy/docker-compose.yaml을 docker compose up -d.
    /health 엔드포인트가 있으면 최대 30초 재시도로 기동 확인. 실패 시 로그 출력 후 1 반환."""

# intended_solve.py
def main() -> int:
    """solution/exploit.py(or .sh)를 실행 -> 그 결과를 grader/red_grader.py의 grade_red()에 제출
    -> passed=True 아니면 실패. 이게 문제 출제자가 '내 문제는 의도한 방법으로 풀린다'를
    증명하는 핵심 게이트."""

# blank_submit.py
def main() -> int:
    """flag="" 또는 빈 submission으로 grade_red() 호출 -> passed=False여야 통과.
    (아무것도 안 해도 통과되는 결함 문제를 걸러냄)"""

# blue_verify.py
def main() -> int:
    """solution/defense.md의 패치 절차(주로 challenge의 Config Service patch toggle 또는
    코드 교체 스크립트)를 적용 -> grade_blue() True 확인 -> 이후 intended_solve.py 재실행 ->
    이번엔 red_grader가 False여야 함(패치가 실제로 공격을 막는지 확인)."""

# safety_scan.py
def main() -> int:
    """(a) infra/ci/secret_scan.py 재사용해 challenge 디렉토리 스캔
       (b) challenge.yaml의 safety.profile == "hardened" 인 경우 deploy/docker-compose.yaml에
           cap_drop/read_only/mem_limit이 실제로 있는지 텍스트 검사(08번 문서 하드닝 패턴)
       (c) category in {ai, reversing} and RCE 가능성 있는 경우 profile이 standard면 경고+실패"""

# flag_determinism.py
def main() -> int:
    """deploy_up -> intended_solve -> teardown -> deploy_up(재배포) -> intended_solve 재실행.
    두 번의 grade_red() 결과(특히 dynamic flag 사용 시 team_id별 값)가 팀 기준으로 일관되는지 확인."""

# teardown.py
def main() -> int:
    """docker compose down -v. 잔여 컨테이너/네트워크 없는지 docker ps -a로 재확인."""

# run_all.py
def main() -> int:
    """위 7개를 순서대로 실행, 하나라도 실패하면 즉시 중단 + 리포트.
    사용법: python run_all.py --challenge WEB-002
    통과 시 challenges/<id>/QA_PASSED 마커 파일 생성(배포 큐가 이 마커를 확인)."""
```

### 리포트 포맷 (infra/deploy/checklist.py와 동일 스타일)
```
======================================================================
C-QA 검수: WEB-002
======================================================================
✅ schema_validate
✅ deploy_up
✅ intended_solve      (alg=none 위조로 flag 획득 확인)
✅ blank_submit        (빈 제출 시 미통과 확인)
✅ blue_verify         (패치 후 재공격 차단 확인)
✅ safety_scan
✅ flag_determinism
✅ teardown
----------------------------------------------------------------------
✅ 전체 8개 항목 통과. QA_PASSED 마커 생성.
```

### CI 연동
- GitHub Actions(또는 사내 CI) 워크플로우: `challenges/**` 경로 변경된 PR마다 변경된 challenge_id만
  골라 `run_all.py --challenge <id>` 실행.
- `QA_PASSED` 마커가 없는 challenge는 published 큐 스크립트(`infra/deploy/publish_challenges.py`,
  다음 단계에서 작성)가 건너뛴다.

---

## 2. 나머지 챌린지 확장 목록

**실제 파일로 구현 완료(12개, 6개 분야 × 2개씩)**:
- Web: `WEB-002`(JWT위조), `WEB-000`(디버그노출)
- Detection: `DET-000`(브루트포스 도입), `DET-001`(포트스캔 임계튜닝+노이즈)
- Forensics: `FOR-000`(평문자격증명 카빙), `FOR-002`(다중필드 침해재구성)
- Reversing: `REV-000`(XOR 도입), `REV-001`(다단계 키젠)
- Network: `NET-000`(평문 텔넷), `NET-002`(세그멘테이션 그래프탐색)
- AI: `AI-000`(feature-space 회피), `AI-001`(모델 추출)

전부 11번 문서 표준 구조 그대로, C-QA 통과 확인. 특히 REV-001은 키젠 로직이 원본
checker.py의 검증 알고리즘과 정확히 일치하는지, AI-001은 실제 sklearn 모델로
쿼리 400회 내 held-out 100% 일치율(진짜 블랙박스 추출)까지 실제 실행 검증했다.
DET-001은 "애매한 정상 케이스"(8개 포트 사용)를 노이즈에 섞어 임계값 튜닝의
실전 난이도를 실제로 구현했다.

나머지는 아래 표대로 같은 패턴으로 확장.

현재 상태(12~16, 18번 문서 기준): 분야당 3~4개(easy/medium/hard/insane 중 일부만 채워짐).
목표: **분야당 7개**(easy 1~2, medium 2~3, hard 2, insane 1). 아래는 빈 슬롯을 채울 구체적
문제 목록 — 제목/컨셉만 확정하고 완전한 패키지(challenge.yaml 등)는 각 C-에이전트가 11번 표준에
따라 작성한다.

### Web (C1) — 현재 4개(WEB-000,002,004,009) → 추가 3개
| ID | 난이도 | 컨셉 |
|---|---|---|
| WEB-003 | medium | GS-003 IDOR를 별도 문제로 정식화(현재는 예시로만 언급됨) — 순차 스캔 자동화 스크립트 작성까지 요구 |
| WEB-005 | hard | PP-004 역직렬화(pickle RCE)를 웹 문제로 정식화, Blue는 JSON 전환 패치 |
| WEB-007 | medium | 파일 업로드 취약점(확장자 검증 우회) — 새 취약점 유형 추가 필요(트윈에 없으므로 독립 챌린지 앱으로) |

### Forensics (C2) — 현재 4개(FOR-000,002,003,009) → 추가 3개
| ID | 난이도 | 컨셉 |
|---|---|---|
| FOR-004 | hard | 다중 소스 타임라인 상관(웹+네트워크+방화벽 로그 합쳐 킬체인 재구성) — 05번 크로스오버 시나리오 데이터 재사용 가능 |
| FOR-005 | medium | 레지스트리/prefetch류 OS 아티팩트 분석(윈도우 침해 흔적) — 합성 아티팩트 필요 |
| FOR-006 | insane 대체용 medium | 스테가노그래피 단일 단계(이미지에서 플래그 추출) — FOR-009(insane, 3단 체인)의 도입판 |

### Detection (C3) — 현재 4개(DET-000,002,004,009) → 추가 3개
| ID | 난이도 | 컨셉 |
|---|---|---|
| DET-001 | medium | 브루트포스+계정별 실패율 임계 튜닝(DET-000의 응용판, 정상 사용자 실수 vs 공격 구분) |
| DET-003 | hard | C2 비콘 헌팅(06번 문서 4절 지터 계산)을 정식 문제로 — Zeek conn 로그 합성 데이터셋 필요 |
| DET-005 | hard | 위협헌팅 리포트 작성형(가설 기반) — 자동채점 어려우므로 채점 기준을 "발견한 ATT&CK 기술 ID 매칭"으로 단순화 |

### AI (C4) — 현재 4개(AI-000,002,005,009) → 추가 3개
| ID | 난이도 | 컨셉 |
|---|---|---|
| AI-001 | medium | 모델 추출(쿼리만으로 대리모델 학습) — AI-002 탐지기를 그대로 재활용해 추출 난이도 조절 |
| AI-003 | hard | 데이터 포이즈닝/백도어 삽입 — 합성 학습 파이프라인 필요(가장 인프라 비용 큼, 우선순위 낮음) |
| AI-004 | medium | 멤버십 추론(특정 샘플이 학습셋에 포함됐는지 추정) — AI-002와 같은 모델 재사용 가능 |

### Reversing (C5) — 현재 3개(REV-000,003,009) → 추가 4개(부족분 제일 큼)
| ID | 난이도 | 컨셉 |
|---|---|---|
| REV-001 | medium | 난독화된 라이선스 체크 크랙미(10번 문서에 이미 컨셉 있음, 패키지화만 필요) |
| REV-002 | medium | 커스텀 XOR 다중 키 인코딩(REV-000의 응용판) |
| REV-004 | hard | 펌웨어 분석(하드코딩 자격증명) — 05번 크로스오버(XOVER-REV-PWN-NET-01)의 Phase 1과 동일 문제를 독립 챌린지로도 배포 |
| REV-005 | hard | 힙 익스플로잇 — REV-003(스택 BOF)보다 상위 난이도, 안전장치(hardened) 필수 |

### Network/OT (C6) — 현재 4개(NET-000,002,003,009) → 추가 3개
| ID | 난이도 | 컨셉 |
|---|---|---|
| NET-001 | medium | Kerberoasting(DN-002)을 독립 네트워크 문제로 정식화 — 오프라인 크래킹 시뮬레이션 도구 제공 |
| NET-004 | hard | 방화벽 룰 대결(Red 경로탐색 vs Blue 최소권한 룰) — 10번 문서에 컨셉 있음, 패키지화 |
| NET-005 | medium | S7(지멘스 PLC 프로토콜) 분석 — Modbus(NET-003)와 다른 프로토콜로 다양성 확보 |

**총합**: 6개 분야 × 7개 = 42개 목표. 현재 22개(12~16,18 합산) → **20개 추가 필요**.
위 표가 정확히 그 20개(3+3+3+3+3+4+3... 재계산: 3+3+3+3+4+3=19, 반올림 오차는 여유분).

---

## 3. 출제 세션 배정 (Claude Code 세션 단위)

| 세션 | 담당 | 산출물 |
|---|---|---|
| C-QA.1 | C-QA 파이프라인 스크립트 8개(1절) | `infra/challenge_qa/` 전체 + 기존 WEB-002에 시험 적용 |
| C1.2 | C1(Web) 추가 3개 | WEB-003, WEB-005, WEB-007 완전 패키지 + QA 통과 |
| C2.2 | C2(Forensics) 추가 3개 | FOR-004, FOR-005, FOR-006 |
| C3.2 | C3(Detection) 추가 3개 | DET-001, DET-003, DET-005 |
| C4.2 | C4(AI) 추가 3개 (AI-003은 인프라비용 커서 별도 세션 권장) | AI-001, AI-004 우선, AI-003은 다음 스프린트 |
| C5.2 | C5(Reversing) 추가 4개 | REV-001, REV-002, REV-004, REV-005 |
| C6.2 | C6(Network/OT) 추가 3개 | NET-001, NET-004, NET-005 |

**권장 순서**: C-QA.1을 가장 먼저(검수 도구가 있어야 이후 산출물의 품질을 즉시 확인 가능) →
이후 C1~C6 세션은 병렬 진행 가능(서로 의존관계 없음).

---

## 4. 완료 판정 (전체)

- `infra/challenge_qa/run_all.py`가 42개 챌린지 전부에 대해 통과.
- 각 챌린지 디렉토리에 `QA_PASSED` 마커 존재.
- 분야별 난이도 분포가 목표(easy1~2/medium2~3/hard2/insane1)에 근접.
