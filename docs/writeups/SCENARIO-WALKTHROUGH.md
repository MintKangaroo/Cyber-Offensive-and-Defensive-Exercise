# 🎬 시나리오 워크스루 — 한 판(Match)의 전 과정

한 번의 훈련(Match)이 **준비 → 시작 → 공방 → 종료·리뷰**로 어떻게 흘러가는지, 실제 명령·화면과 함께 따라갑니다. 예시는 **IT→OT 피벗 크로스오버**(사내망 침투 → 정유 플랜트 사보타주)를 축으로 합니다.

---
## 0. 준비 (교관)
```bash
# 1) 코어 스택 + 트윈 기동
docker compose up -d event_collector scoring_engine config_service edr_backend siem_api \
  scenario_engine instructor_api aar_report noc_monitor challenge_portal \
  ground_station power_plant defense_network refinery_plant \
  gs_gateway pp_gateway dn_gateway refinery_plant_gw
# 2) 대시보드 5개(dev 서버) — Red 5176 / Blue 5177 / EDR 5173 / SIEM 5175 / LiveFire 5174
# 3) 클린 상태 확인: 이벤트 0, 점수 0, 패치 0 (안 그러면 초기화)
python3 shared/safe_probe.py --summary     # 전 취약점 VULNERABLE = 시작점 정상
```
- 팀 배정: `docs/TEAMS.md`의 접속 카드 배포(레드 알파/브라보, 블루 알파/브라보).
- Live Fire를 **INSTRUCTOR** 역할로 열어 전체 상황 관전.

---
## 1. 시작 — 정찰 (T+0)
**🔴 Red**가 Red Portal에서 팀 선택 후 정찰 시작.
```bash
HOST=100.64.140.27
curl -s http://$HOST:8003/health          # 사내망 트윈 확인
```
Live Fire: 아직 전 자산 `SECURE`, 이벤트 피드 비어 있음.

---
## 2. 초기 침투 — IT (T+5)
Red가 사내망(defense_network, 8003)의 취약점을 공략.
```bash
# DN-002 Kerberoastable 계정 열람 → 자격증명 확보
curl http://$HOST:8003/api/ad/service-accounts
# DN-001 SMB 익명 접근으로 파일 수집
curl http://$HOST:8003/api/smb/shares
```
- **이벤트**: `red_attack_started(defense_network, DN-002, initial_access)` → Live Fire 토폴로지에서 사내망이 `UNDER_ATTACK`(주황).
- **🔵 Blue**: Blue Portal 인시던트 피드에 "공격 개시 defense_network" 표시 → **즉시 대응 판단**.

---
## 3. 방어 1차 대응 (T+7)
Blue가 병렬로 움직임:
- **EDR 콘솔**: 사내망 호스트에서 의심 프로세스 확인 → 필요 시 격리.
- **Blue Portal 패치 보드**: `DN-001`, `DN-002` 패치 토글 → 재접근 차단.
- **SIEM 콘솔**: `service-accounts` 접근 로그 확인 → 탐지 챌린지로 규칙화.

패치가 반영되면 Red의 같은 요청은 **401**로 막힘:
```bash
curl -s -o /dev/null -w "%{http_code}\n" http://$HOST:8003/api/ad/service-accounts   # → 401
```

---
## 4. 피벗 — IT→OT (T+12)
Red가 탈취한 자격증명으로 **정유 플랜트(refinery_plant, 8201)** 로 횡이동, OPC UA 정찰.
```bash
# REF-001 OPC UA 익명 태그 열람 → DCS/SIS 태그 정찰
curl "http://$HOST:8201/api/opcua/read?node=ns=2;s=SIS.HH_Trip.Setpoint"
```
- **이벤트**: `red_attack_started(refinery_plant, lateral_movement)`.
- **Process Impact**(Live Fire): 아직 정유 `정상`(SIS 인터록 정상).

---
## 5. 임팩트 — OT 사보타주 (T+18)
Red가 안전계장(SIS)을 무단 우회 → **목표 달성**.
```bash
# REF-002 SIS Safety Bypass (승인 없이 안전 트립 우회)
curl -X POST http://$HOST:8201/api/sis/bypass -H 'Content-Type: application/json' -d '{}'
```
- **이벤트**: `red_objective_success(refinery_plant, objective)` + (미대응 시) `asset_compromised`.
- **Process Impact**: 정유 DCS/SIS → **사보타주** (SIS 인터록 해제 · 반응기 과압 34.5bar, 빨강).
- **Red Portal**: 분석형 ICS 챌린지(ICS-009 FF MODE O/S 등)도 병행 풀이로 점수 누적.

---
## 6. 방어 최종 대응·복구 (T+20)
Blue:
1. **EDR로 정유 자산 격리** → 확산 차단.
2. **패치 보드**에서 `REF-001`, `REF-002` 패치.
3. **탐지 챌린지 제출**(예: DET-008 FF MODE_BLK O/S, DET-011 S7 안전DB) → SIEM 규칙으로 자동탐지 + blue 점수.
4. `safe_probe --asset refinery_plant --watch 20`으로 패치 반영 확인.
- 패치 + health 3회 정상 → **`asset_recovered`(+50)**, Process Impact가 `복구중`(청록) → `정상`.

---
## 7. 종료 — AAR (T+30)
교관이 시나리오 종료. **AAR(After-Action Report, 8090)** 가 자동 생성:
- **MTTD**(평균 탐지시간) / **MTTR**(평균 복구시간)
- 탐지율 / 오탐률
- **ATT&CK / ATT&CK for ICS 히트맵** (T0836 무단제어, T0858 안전우회 등)
- PDF 리포트
```bash
curl -s http://$HOST:8090/health     # AAR 서비스 확인, 리포트 생성 트리거는 instructor API
```

---
## 점수 흐름 요약
| 시점 | Red | Blue |
|---|---|---|
| 초기 침투(DN) | red_attack_started +점수 | 탐지 규칙 작성 시 +점수 |
| 피벗(REF 정찰) | lateral +점수 | — |
| 사보타주(SIS) | objective +100 / 챌린지 red점수 | — |
| 대응·복구 | (은밀성 실패 시 감점 요소) | 패치·복구 +50, 탐지챌린지 blue점수 |
| 크로스오버 완주 | chain bonus +50 | MTTD/MTTR 짧을수록 유리 |

## 재현 가능한 초기화
한 판이 끝나면 **Baseline으로 리셋**해 다음 판을 동일 조건에서 시작합니다(→ [P1: Reset/Snapshot 기능](../../services/range_control/README.md) 참조). 리셋 후 `safe_probe` 전수 통과 + health 통과여야 다음 훈련 시작.
