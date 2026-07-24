# 교관 운영 매뉴얼 — 훈련 당일 런북

> 지금까지는 전부 "만드는" 문서였다. 이건 "다 만든 걸 실제로 어떻게 돌리는가"에 대한
> 교관(진행자) 관점 실행 매뉴얼. 만드시는 팀이 직접 교관 역할도 겸할 걸 감안해 작성.

---

## 1. 훈련 전 (D-1)

### 1.1 배포 체크리스트 (자동화된 것 그대로 실행)
```bash
python infra/deploy/checklist.py --repo-root .
python infra/ci/isolation_test.py     # Docker 환경에서 실제 실행(21번 문서 M1 이후 가능)
```
7개 항목 전부 통과 확인. 하나라도 실패하면 **훈련 시작하지 말 것**.

### 1.2 시나리오 선택 및 사전 로드
- `scenarios/single/` 또는 `scenarios/crossover/`에서 이번 훈련에 쓸 시나리오 확정.
- 난이도가 참가팀 수준과 맞는지 재확인(18번 문서의 easy~insane 분포 참고).
- `POST /instructor/scenario/start`는 **훈련 당일 시작 직전에** 호출(미리 활성화하면 대기시간
  동안 취약점이 이미 열려 있어 형평성 문제 생김).

### 1.3 참가팀 계정/토큰 준비
- 팀별 `X-Team-Id` 값 배포(예: `team_alpha`, `team_blue1` 등). 동적 플래그(11번 문서)가 이
  값으로 HMAC 계산되므로 팀별로 반드시 달라야 함.
- 교관 토큰(`INSTRUCTOR_TOKEN`)은 교관만 소지, 참가팀에 절대 공유 금지.

### 1.4 관전자/대시보드 접속 준비
- 관전자용 URL과 역할(observer)이 제대로 스코프 제한되는지 사전 확인(24번 문서 4절의 인증
  확장이 아직이면, MVP 단계에서는 "관전자에게 교관 콘솔 URL을 안 알려주는" 수준의 운영적
  통제로 대체 — 코드 레벨 인증 전까지는 운영으로 커버).

### 1.5 리허설
- 팀 하나를 교관이 직접 Red 역할로 돌며 시나리오 stage 1개 이상 실제로 완주해보기.
- Blue 쪽도 safe_probe 실행 → patch_console로 패치 1건 실제 적용해보기.
- NOC/EDR 대시보드에 반응이 뜨는지 확인.

---

## 2. 훈련 당일 — 시작 전 (D-Day, 시작 1시간 전)

```bash
# 1) 서버 리소스 확인
docker stats --no-stream

# 2) 전 서비스 health 확인
for port in 8001 8002 8003 8010 8020 8030 8080; do
  curl -s localhost:$port/health || echo "PORT $port DOWN"
done

# 3) safe_probe로 초기 상태(전부 vulnerable) 확인
python shared/safe_probe.py

# 4) 노이즈 생성기 시작(시나리오에 설정되어 있으면 자동, 수동이면 여기서)
```

## 3. 훈련 진행 중

### 3.1 정상 진행 시 교관의 역할
- 대시보드(Live Fire)로 전체 진행 관전. 개입 최소화가 원칙 — 훈련은 참가팀이 주도.
- Instructor Console의 이벤트 수동주입은 **정말 필요할 때만**(예: 특정 팀이 완전히 막혀서
  다음 단계로 못 넘어갈 때 힌트성 이벤트) — 남용하면 채점 신뢰성이 깨짐(모든 개입은 audit에
  남고 reason이 강제되는 이유가 이것).

### 3.2 이상 상황별 대응

| 상황 | 대응 |
|---|---|
| 특정 트윈이 응답 없음(NOC 대시보드 빨강) | 먼저 Red의 정상 공격 결과인지 확인(DoS성 익스플로잇). 의도된 거면 Blue가 복구하는 것도 훈련의 일부 — 개입하지 말 것. 인프라 장애로 판단되면 `docker compose restart <service>` |
| 한 팀이 명백히 비정상적 방법으로 점수 획득(치팅 의심) | `/scores/reconcile`로 정합성 확인 → `/instructor/audit`로 이벤트 이력 대조 → 필요시 `/instructor/score/adjust`로 정정(사유 상세 기록) |
| 훈련 전체가 통제 불능(예상 못한 부하, 무한루프성 공격) | `POST /instructor/killswitch` 즉시 발동 → 원인 파악 후 `/instructor/killswitch/release` |
| 특정 팀의 공격이 다른 팀에게 영향(격리 설계상 원래 안 되어야 하지만) | 즉시 `isolate_host` 해당 자산 격리 + 네트워크 격리 회귀 테스트 재실행으로 원인 조사 |
| Blue팀이 패치했는데 safe_probe가 여전히 vulnerable로 나옴 | Config Service 캐시 지연(트윈 폴링 주기 4초) 확인 → 그래도 안 바뀌면 Config Service 자체 상태(`GET /config/patches`) 직접 확인 |

### 3.3 중간 안내 방송 타이밍 (권장)
- 시작 10분 후: "모든 팀 텔레메트리 확인되나요?" (연결 문제 조기 발견)
- 중간 지점: 남은 시간 안내, Blue팀에 "탐지·복구도 점수임" 재환기(공격에만 집중하는 경향 방지)
- 종료 5분 전: 마무리 안내

---

## 4. 훈련 종료 직후

```bash
# 1) 시나리오 종료(최종 점수 스냅샷)
curl -X POST http://localhost:8050/instructor/scenario/end \
  -H "Authorization: Bearer $INSTRUCTOR_TOKEN" \
  -d '{"scenario_id":"SAT-KILLCHAIN-01","reason":"training ended on schedule"}'

# 2) 최종 점수/정합성 확인
curl http://localhost:8020/scores?scenario_id=SAT-KILLCHAIN-01
curl http://localhost:8020/scores/reconcile?scenario_id=SAT-KILLCHAIN-01

# 3) AAR 리포트 생성(27번 문서)
curl http://localhost:8090/report/aar?scenario_id=SAT-KILLCHAIN-01 -o aar_report.json
```

**킬스위치를 걸지 말 것**: 종료 직후엔 리플레이/AAR 생성을 위해 데이터를 그대로 살려둬야 함.
킬스위치는 "긴급 정지"용이지 "정상 종료" 절차가 아니다.

---

## 5. 디브리핑 (After-Action Review 세션)

### 5.1 진행 순서 (권장 60~90분)
1. **전체 요약** (5분): 최종 점수, 시나리오 개요 — AAR 리포트 요약 페이지 그대로 활용.
2. **리플레이** (20분): Live Fire Dashboard의 Replay 기능으로 주요 순간 재생(07번 문서 1절).
   특히 "최초 침투 → 최초 탐지" 구간을 배속 조절해가며 같이 봄.
3. **Red 팀 발표** (10분): 어떤 경로로 침투했는지, 어디서 막혔는지.
4. **Blue 팀 발표** (10분): 무엇을 탐지/못했는지, 패치 우선순위를 어떻게 정했는지.
5. **ATT&CK 커버리지 리뷰** (10분): 이번 훈련에서 탐지 못한 기술이 있었다면(27번 문서
   AttackMatrix) 왜 놓쳤는지 논의.
6. **개선 액션 아이템 정리** (10분): AAR의 자동 추천 코멘트(27번 문서 1.4절)를 출발점으로.

### 5.2 다음 훈련 반영
- 이번 훈련에서 드러난 룰셋 갭(ATT&CK 커버리지 빈칸)을 06번 문서 탐지 룰셋에 추가.
- 난이도가 너무 쉬웠거나 어려웠으면 18번 문서 난이도 곡선 재조정(정답률/소요시간 기록 활용,
  11번 문서 4절 캘리브레이션 절차).

---

## 6. 다중 교관 운영 시 역할 분담 (참가 규모가 커질 경우)

| 역할 | 책임 |
|---|---|
| Lead Instructor | 전체 진행, 킬스위치 등 중대 결정 권한 |
| Technical Support | 인프라 이상 대응, `docker compose` 레벨 트러블슈팅 |
| Red Team Liaison | Red팀 질의응대, 힌트 승인 여부 판단 |
| Blue Team Liaison | Blue팀 질의응대, patch_console/EDR 사용법 지원 |

---

## 7. 체크리스트 요약 (인쇄해서 당일 옆에 두고 볼 것)

```
[ ] D-1: 배포 체크리스트 7항목 통과
[ ] D-1: 시나리오 확정 + 리허설 완료
[ ] D-Day: 전 서비스 health 확인
[ ] D-Day: safe_probe로 초기 vulnerable 상태 확인
[ ] 시작: scenario/start 호출(당일 직전에)
[ ] 진행 중: 대시보드 상시 관전, 개입 최소화
[ ] 종료: scenario/end -> reconcile 확인 -> AAR 생성
[ ] 디브리핑: 리플레이 + ATT&CK 커버리지 리뷰
[ ] 사후: 룰셋/난이도 개선 항목 기록
```
