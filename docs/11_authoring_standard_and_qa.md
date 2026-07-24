# 출제 표준 & 검수 자동화 (C0 / C-QA) — Claude Code 빌드 프롬프트

> C1~C6 분야 에이전트가 공통으로 따르는 문제 표준과, C-QA의 자동 검수 파이프라인.
> 목표: 문제의 재현성·정답 유일성·안전성·자동채점을 표준화해 대량 출제를 신뢰성 있게.

---

## 1. 문제 리포 구조 (표준)

```
challenges/
  <category>/<challenge_id>/
    challenge.yaml        # 메타 + 채점 정의(10번 문서 포맷)
    deploy/               # 취약 환경(docker-compose 조각 or 트윈 연동 설정)
      docker-compose.yaml
      app/ ...
    solution/             # 정답(비공개, 검수·채점용)
      exploit.sh|py       # 의도된 공격 해법(Red 자동 검증)
      defense.md|rules/   # 의도된 방어 해법(Blue 기준)
      flag.txt            # 확정 플래그(해시로도 보관)
    grader/               # 자동 채점기
      red_grader.py       # flag/이벤트 기반
      blue_grader.py      # safe_probe/alert/patch 기반
    tests/                # C-QA 검수용
      test_reproducible.py
    writeup.md            # 훈련 후 공개 해설
    metadata.json         # 난이도 태그, ATT&CK, 예상 소요, 의존성
```

---

## 2. 채점 계약 (Grader Contract)

모든 문제는 두 개의 grader를 제공하고, 아래 인터페이스를 준수:

```python
# red_grader.py
def grade_red(submission: dict, context: dict) -> GradeResult:
    """submission: {flag?, team_id, ...}. context: 배포 엔드포인트/토큰.
    반환: GradeResult(passed: bool, points: int, detail: str)"""

# blue_grader.py
def grade_blue(context: dict) -> GradeResult:
    """safe_probe/alert/patch 상태를 확인해 방어 성공 판정."""
```

- **Red 채점 방식**: `flag_match`(정적 플래그), `dynamic_flag`(팀별 유니크 플래그로 공유 방지), `event`(Event Collector에 특정 이벤트 도달).
- **Blue 채점 방식**: `safe_probe`(패치 확인), `alert`(SIEM에 기대 알림 발생), `patch_check`(설정/버전 검증), `block`(공격 재시도가 차단됨).
- **동적 플래그 권장**: `flag{<hmac(team_id, secret)>}`로 팀마다 다르게 → 플래그 공유 치팅 방지.

---

## 3. C-QA 자동 검수 파이프라인

문제가 배포 큐에 들어가기 전 CI에서 자동 실행:

```
[1] schema_validate   : challenge.yaml이 표준 스키마 준수하는가
[2] deploy_up         : deploy/ 컨테이너가 정상 기동하는가(헬스체크)
[3] intended_solve    : solution/exploit로 red_grader가 PASS 하는가(의도 해법 성립)
[4] blank_submit      : 아무것도 안 하면 red_grader가 FAIL 하는가(빈 제출 방어)
[5] blue_verify       : 의도된 방어 적용 후 blue_grader PASS + red 재시도 FAIL
[6] unintended_scan   : 알려진 비의도 해법 패턴 스캔(선택, 휴리스틱)
[7] safety_scan       : 실데이터/실시크릿 없음, 격리 요구 충족(08 연계)
[8] flag_determinism  : 동일 조건 재배포 시 채점 결과 동일
[9] teardown          : 컨테이너 정리, 리소스 누수 없음
```

- 하나라도 실패하면 배포 차단 + 리포트. C-QA 에이전트가 리포트 검토.
- **[3]+[4] 조합이 핵심**: "의도 해법으론 풀리고, 안 풀면 안 통과"가 최소 보증.
- **[5]가 Red↔Blue 균형 보증**: 방어가 실제로 공격을 막는지 확인.

---

## 4. 난이도 캘리브레이션

- 난이도 표기(easy~insane)와 실제가 어긋나는 걸 막기 위해, 파일럿 풀이 데이터(첫 배포 후 정답률/평균 소요)를 수집해 재조정.
- `metadata.json`에 `expected_solve_min`, `first_blood_target` 기록 → 실제와 비교.
- 힌트 비용/개수도 난이도에 맞게(easy는 힌트 적게, insane은 단계적 힌트).

---

## 5. 안전 게이트 (필수)

- 모든 문제 컨테이너는 08 안전장치 적용: internal 네트워크, egress 차단(허용 목적지만), cap_drop, read-only(가능한 경우), 리소스 제한.
- solution/과 flag는 비공개 저장소/암호화. 참가자 환경에 절대 노출 안 됨.
- AI/Pwn/역직렬화 등 RCE류 문제는 저권한·강격리 프로파일 강제(스키마에서 `safety.profile: hardened` 요구).

---

## 6. 배포 & 라이프사이클

```
draft → C-QA CI → review → staging(내부 플레이테스트) → published → (시즌 종료) archived + writeup 공개
```

- 시즌/라운드 편성은 C0가 분야 밸런스·난이도 곡선 고려해 배치.
- published 이후 unintended 발견 시 hotfix 또는 무효화 절차.

## 7. Definition of Done

- 새 문제를 표준 구조로 넣고 CI 돌리면 9단계 검수가 자동 실행.
- 의도 해법 성립 + 빈 제출 방어 + 방어가 공격을 막음이 자동 확인.
- 동적 플래그로 팀별 유니크, 안전 게이트 통과한 문제만 published.
