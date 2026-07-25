# 다중 팀 테넌트 격리 (P1 #9) — Range → Match → Team → Twin Set

실전 대회 운영을 위한 테넌시 계층과 구현 현황·로드맵.

```
Range (물리/논리 훈련장)
 ├─ Match A (한 판)
 │   ├─ Red Team A     ─┐
 │   ├─ Blue Team A     ├─ scenario_id = match_A  (이벤트·점수 파티션 키)
 │   └─ Twin Set A      ┘
 └─ Match B
     ├─ Red Team B     ─┐
     ├─ Blue Team B     ├─ scenario_id = match_B
     └─ Twin Set B      ┘
```

모든 데이터에 **`range_id` · `match_id` · `team_id`** 가 붙습니다. Match 레지스트리(`range_control`)가
이 매핑의 단일 출처(SoT)입니다.

## Match 레지스트리 (range_control 8055)
| 메서드 | 경로 | 설명 |
|---|---|---|
| POST | `/matches` | Match 생성 {range_id, match_id, red_teams, blue_teams, twin_set, scenario_id?} |
| GET | `/matches` (`?range_id=`) | Match 목록(교관 전용) |
| GET | `/matches/{id}` | Match 상세(team_index 포함) |
| GET | `/matches/{id}/scoreboard` | 해당 Match 점수(scenario_id 파티션) |
| DELETE | `/matches/{id}` | Match 삭제 |

`scenario_id` 미지정 시 `match_id`를 씁니다 → **per-match 이벤트 스트림/점수가 그대로 분리**됩니다.

## 요구 기능 vs 구현 현황

| 요구 기능 | 현황 | 구현 방식 |
|---|---|---|
| **팀별 플래그 키** | ✅ 구현 | 챌린지 플래그가 `HMAC(CHALLENGE_SECRET, "ID:team_id")` — 팀마다 유니크(답 공유 불가) |
| **팀별 이벤트 스트림** | ✅ 구현 | 이벤트에 `scenario_id`·`team_id`. `GET /replay/events?scenario_id=match_X` 로 매치 스코프 |
| **팀별 점수 정책** | ✅ 구현 | 점수가 `scenario_id`로 버킷팅. `GET /scores?scenario_id=match_X` |
| **팀 간 직접 접근 차단** | ✅ 구현 | per-twin `internal` 네트워크(형제 트윈 도달 불가) — 격리 테스트 실측 |
| **인터넷 egress 차단** | ✅ 구현 | 11개 트윈 `internal:true` — 외부 도달 불가 |
| **교관만 전체 Match 조회** | ✅ 구현 | `/matches`·`/safety/*`·`/admin/*` 전부 instructor 토큰(RBAC) 게이트 |
| **관전자 공개정보 지연** | ✅ 구현(P3) | `/events/delayed?delay_sec=N` — N초 지난 이벤트만. Live Fire observer 역할이 30s 지연 피드 폴링 + 헤더 표시. RBAC observer 게이트 |
| **매치별 트윈 셋(물리 격리)** | ✅ 구현(P2) | `scripts/deploy_match.sh` — 별도 compose 프로젝트로 트윈 인스턴스 복제, 매치별 internal 네트워크 → cross-match 도달 차단·egress 차단(실측) |
| **팀별 동적 포트** | ✅ 구현(P2) | 배포 시 port_base 오프셋(match_a 8301~, match_b 8401~). 매치별 이벤트는 `MATCH_SCENARIO_ID`로 scenario 파티션(실측) |
| **팀별 서브도메인** | 🔷 로드맵 | 동적 포트는 구현. 서브도메인(리버스프록시 vhost)은 후속 |

## 지금 바로 다중 매치 운영하는 법 (공유 트윈 셋)
가장 단순·안전한 운영 모델은 **매치별 scenario_id 분리 + 공유 트윈 셋**입니다.
```bash
# 매치 생성(교관)
curl -X POST localhost:8055/matches -H "Authorization: Bearer $INSTRUCTOR_TOKEN" \
  -d '{"range_id":"r1","match_id":"match_A","red_teams":["red_alpha"],"blue_teams":["blue_alpha"],"twin_set":["refinery_plant","power_plant"]}'
# 각 팀은 자기 team_id로 포털 진입 → 이벤트/점수가 scenario_id=match_A로 분리
# 교관은 매치별 스코어보드만 조회: GET /matches/match_A/scoreboard
```
- 팀별 플래그는 HMAC(team_id)로 이미 유니크 → 트윈을 공유해도 답 공유 불가.
- 팀 간 직접 트래픽·egress는 트윈 격리로 차단.

## 매치별 트윈 셋 물리 배포 (P2, 구현됨)
교관이 호스트에서 실행(range_control 서비스는 docker 소켓 미노출, #11 준수):
```bash
export INSTRUCTOR_TOKEN=...            # range_control 등록용(선택)
scripts/deploy_match.sh match_a 8300  # 정유8301/팩토리8302/수도8303, scenario=match_a
scripts/deploy_match.sh match_b 8400  # 8401~8403, scenario=match_b
scripts/teardown_match.sh match_a     # 정리(코어 disconnect + 프로젝트 down)
```
구조: 별도 compose 프로젝트(`-p match_a`, `infra/match/docker-compose.match.yml`)로 트윈 인스턴스
복제. `twinnet`(internal:true)로 egress·cross-match 차단, 게이트웨이는 `edge`로 오프셋 포트 게시,
코어(event_collector/config/edr/siem)는 스크립트가 매치 twinnet에 connect해 트윈→코어만 허용.
트윈은 `MATCH_SCENARIO_ID`로 자기 매치 이벤트를 태깅 → per-match 이벤트/점수 완전 격리.

**실측 검증**(match_a + match_b 동시 배포):
- 포트 격리: 8301~8303 / 8401~8403 각각 200 ✓
- cross-match 차단: match_a 트윈 → match_b 트윈 `gaierror`(도달 불가) ✓
- egress 차단: match_a 트윈 → 8.8.8.8 `OSError` ✓
- 코어 도달: match_a 트윈 → event_collector 허용 ✓
- 이벤트 파티션: match_a 공격 → `scenario_id=match_a`, match_b → `scenario_id=match_b` ✓

## Phased 로드맵
1. **P1(완료)**: Match 레지스트리 + scenario_id 파티션 + 팀별 HMAC 플래그 + RBAC + 교관 UI.
2. **P2(완료)**: 매치별 트윈 셋 물리 배포(deploy_match.sh) — 프로젝트 격리 + internal 네트워크 +
   동적 포트 + MATCH_SCENARIO_ID 이벤트 태깅. cross-match/egress 차단·이벤트 격리 실측.
3. **P3(진행)**: ✅ 관전자 지연 큐(`/events/delayed`, Live Fire observer 30s 지연) · ✅ 매치별 플래그
   회전(포털 match_id → 복합 팀키 `match::team`, 같은 팀도 매치마다 다른 플래그·cross-match 거부 실측).
   🔷 남음: 매치별 서브도메인(vhost), 매치 트윈 셋 11섹터 전체 확장.

## 관련
- 초기화·베이스라인: [../services/range_control/README.md](../services/range_control/README.md) (P1 #10)
- 안전 통제: `GET /safety/status`, `POST /safety/emergency-stop` (P1 #11)
- 팀 접속: [TEAMS.md](TEAMS.md)
