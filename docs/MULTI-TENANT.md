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
| **관전자 공개정보 지연** | ⚙️ 부분 | RBAC observer 역할 존재. 지연 표시(delay buffer)는 대시보드 폴링 간격 조정으로 근사, 전용 지연 큐는 후속 |
| **팀별 네트워크 namespace** | 🔷 로드맵 | 현재는 자산(트윈) 단위 격리. 팀별 트윈 인스턴스 복제(Twin Set) 시 팀별 netns로 확장 |
| **팀별 동적 포트/도메인** | 🔷 로드맵 | 게이트웨이가 자산당 고정 포트. 매치별 트윈 셋 배포 시 포트/서브도메인 동적 할당 |

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

## Phased 로드맵 — 완전 물리 격리(Twin Set per Match)
1. **P1(완료)**: Match 레지스트리 + scenario_id 파티션(이벤트/점수/스트림) + 팀별 HMAC 플래그 + RBAC.
2. **P2**: 매치별 트윈 셋 배포 — compose 오버레이/프로젝트 네임(`-p match_A`)로 트윈 인스턴스 복제,
   매치별 `twin_<asset>_<match>` internal 네트워크 + 게이트웨이 동적 포트 할당.
3. **P3**: 매치별 netns/서브도메인, 관전자 지연 큐(공개정보 N초 지연), 매치별 CHALLENGE_SECRET 회전.

## 관련
- 초기화·베이스라인: [../services/range_control/README.md](../services/range_control/README.md) (P1 #10)
- 안전 통제: `GET /safety/status`, `POST /safety/emergency-stop` (P1 #11)
- 팀 접속: [TEAMS.md](TEAMS.md)
