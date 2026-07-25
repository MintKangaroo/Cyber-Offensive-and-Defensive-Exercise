# 팀 접속 안내 (Team Access Card)

훈련 참가자에게 나눠줄 팀별 접속 카드입니다. `<HOST>` 는 서버 IP(예: Tailscale IP `100.64.140.27`)로 바꿔 배포하세요.

## 팀 구성 (기본)
| 팀 | team_id | 진영 | 사용 포털 |
|---|---|---|---|
| 🔴 레드 알파 | `red_alpha` | 공격 | Red Portal |
| 🔴 레드 브라보 | `red_bravo` | 공격 | Red Portal |
| 🔵 블루 알파 | `blue_alpha` | 방어 | Blue Portal |
| 🔵 블루 브라보 | `blue_bravo` | 방어 | Blue Portal |

> 팀 목록은 포털 상단 드롭다운에서 선택합니다(자유 입력 아님 → 오타로 점수판이 갈라지지 않음).
> 팀 구성을 바꾸려면 `challenge_portal` 에 `PORTAL_TEAMS` 환경변수(JSON)를 주면 됩니다:
> `PORTAL_TEAMS='[{"team_id":"red_a","name":"레드 A","side":"red"}, ...]'`

## 접속 주소
| 역할 | 대시보드 | 주소 |
|---|---|---|
| 🔴 Red | **Red Portal** (챌린지·플래그 제출) | `http://<HOST>:5176` |
| 🔵 Blue | **Blue Portal** (인시던트·패치·탐지규칙) | `http://<HOST>:5177` |
| 🔵 Blue | EDR 콘솔 (격리/kill) | `http://<HOST>:5173` |
| 🔵 Blue | SIEM 콘솔 (로그·탐지) | `http://<HOST>:5175` |
| 🎓 운영/관전 | Live Fire (상황판·점수) | `http://<HOST>:5174` |

## 진행 방법
- **레드팀**: Red Portal에서 자기 팀 선택 → 챌린지 풀이(분석형은 아티팩트 다운로드, 서비스형은 트윈 직접 익스플로잇) → 플래그 제출. 팀별 동적 플래그라 답 공유 불가.
- **블루팀**: Blue Portal에서 자기 팀 선택 → ①인시던트 피드로 공격 파악 → ②패치 보드로 취약점 차단 → ③탐지 챌린지로 SIEM 규칙 작성·제출.
- **운영진**: Live Fire로 전체 상황·점수 관전(INSTRUCTOR 역할로 시나리오 주입·점수 조정).

## RBAC 토큰(선택)
백엔드는 역할별 토큰(`.env` 의 `INSTRUCTOR_TOKEN`/`RED_TOKEN`/`BLUE_TOKEN`/`OBSERVER_TOKEN`)을 지원합니다.
`OBSERVER_READ_ENFORCE=1` 로 읽기 접근까지 토큰을 강제할 수 있습니다(기본은 대시보드 편의를 위해 공개).
패치 토글은 instructor 권한이 필요하며, Blue Portal은 서버측에서 instructor 토큰으로 대리 인가합니다(블루 클라이언트엔 토큰 미노출).
