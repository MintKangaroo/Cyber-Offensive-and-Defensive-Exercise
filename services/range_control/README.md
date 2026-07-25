# Range Control (P1 #10) — Reset · Snapshot · Rollback

훈련(Range/Match)의 **재현 가능한 초기화** 운영 서비스. 각 스테이트풀 서비스의 `/admin/reset`
(instructor 인증)을 오케스트레이션하고, Baseline 스냅샷 대비 드리프트를 재고, 리셋 후
`safe_probe` 전수 + 전 서비스 health 통과를 검증한다. **docker 소켓을 노출하지 않는다**(HTTP만).

## 흐름
```
Baseline Snapshot → Scenario Start → Exercise Runtime → (Evidence Export) → Reset → Baseline Verification
```

## 엔드포인트 (포트 8055)
| 메서드 | 경로 | 설명 | 인증 |
|---|---|---|---|
| POST | `/ranges/{range_id}/snapshot` | 현재 상태(이벤트/패치)를 baseline으로 저장 | instructor |
| POST | `/ranges/{range_id}/reset` | 이벤트·점수·solve·패치 초기화(각 서비스 admin reset) | instructor |
| GET | `/ranges/{range_id}/drift` | baseline 대비 현재 상태 차이 | — |
| POST | `/ranges/{range_id}/verify-baseline` | 전 서비스 health + safe_probe 전수 VULNERABLE + 이벤트 클린 | instructor |

리셋 대상: `event_collector`(이벤트), `scoring_engine`(점수/achievement), `config_service`(패치),
`challenge_portal`(red/blue solve).

## 실행
**호스트 사이드 권장** — `verify-baseline`의 `safe_probe`가 트윈 게시포트(localhost:8001~8208)에
접근하기 때문. (reset/snapshot/drift는 서비스명 HTTP라 컨테이너로도 동작.)
```bash
set -a; source .env; set +a
INSTRUCTOR_TOKEN="$INSTRUCTOR_TOKEN" python3 -m uvicorn services.range_control.main:app \
  --host 0.0.0.0 --port 8055
```
compose 서비스로도 제공(`docker compose up -d range_control`) — reset/snapshot/drift 용도.

## 예시
```bash
AUTH="Authorization: Bearer $INSTRUCTOR_TOKEN"; RC=http://localhost:8055
curl -X POST $RC/ranges/match_A/snapshot -H "$AUTH" -d '{"reason":"start"}'
curl -X POST $RC/ranges/match_A/verify-baseline -H "$AUTH"     # → passed:true 면 시작 가능
# ...훈련 진행...
curl $RC/ranges/match_A/drift                                  # 얼마나 변했나
curl -X POST $RC/ranges/match_A/reset -H "$AUTH" -d '{}'       # 다음 판 위해 초기화
curl -X POST $RC/ranges/match_A/verify-baseline -H "$AUTH"     # 다시 passed:true 확인
```

## 설계 노트
- **선언적 baseline**: 각 자산의 초기 DB seed·서비스 상태·패치 상태·계정/토큰은 컨테이너 이미지와
  seed로 관리되고, 런타임 변경분(이벤트/점수/패치/solve)만 reset이 되돌린다. 완전한 파일 해시·
  프로세스·네트워크 정책 baseline 선언은 후속 확장 여지(현재는 관측 상태 기반 드리프트).
- Reset 후 `verify-baseline` 통과(health + 전 취약점 open + 이벤트 클린)여야 다음 훈련을 시작한다.
