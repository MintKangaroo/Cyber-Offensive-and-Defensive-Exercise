#!/usr/bin/env bash
# U-6 소크 오케스트레이터 — 코어 스택 최소구성 기동 → 지속부하 + 메모리 샘플링을
# SOAK_DURATION_SEC 동안 수행 → teardown → 분석. 단일 엔트리포인트(백그라운드 실행 가능).
#
# 가속 소크(2h) 기본. 8시간 정식 소크는 SOAK_DURATION_SEC=28800 로 실행.
#
# 환경변수:
#   SOAK_DURATION_SEC (기본 7200)   SOAK_RATE (기본 40)
#   SOAK_SAMPLE_INTERVAL (기본 60)  SOAK_KEEP_UP=1  (분석 후 스택 유지)
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"    # cyber-range-platform/
RESULTS="$HERE/results"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$RESULTS"

export SOAK_DURATION_SEC="${SOAK_DURATION_SEC:-7200}"
export SOAK_RATE="${SOAK_RATE:-40}"
export SOAK_SAMPLE_INTERVAL="${SOAK_SAMPLE_INTERVAL:-60}"
export SOAK_SAMPLE_CSV="$RESULTS/mem_samples.${STAMP}.csv"
export SOAK_SUMMARY="$RESULTS/load_summary.${STAMP}.json"

# dev 우회(부하 스크립트는 토큰 없이 수집) + 더미 시크릿(fail-closed 회피).
# SERVICE_TOKEN 을 명시적으로 비워 .env 의 실토큰 주입을 무력화 → 이 격리 소크 스택은
# CI loadtest.yml 과 동일하게 dev-mode ingest 로 동작(토큰 없는 부하가 /events 통과).
export RBAC_ALLOW_INSECURE_DEV="true"
export SERVICE_TOKEN=""
export CHALLENGE_SECRET="${CHALLENGE_SECRET:-soak-dummy-secret}"
# 자산 체크포인트 자동 재료화를 소크 동안 자주 트리거해 fold/영속 경로를 지속 스트레스한다
# (부하는 scenario_id 를 실어 보냄). 기본 250: 체크포인트가 자주 나되 매 배치는 아니게.
export ASSET_CHECKPOINT_EVERY="${ASSET_CHECKPOINT_EVERY:-250}"

# aar_report 포함(audit/102 R-1): 소크로 events.db 가 커진 뒤 종료 시 AAR PDF·reconcile 이
# OOM 없이 생성되는지 판정한다(무한 replay 회귀 방지). SAMPLED 는 RSS 슬로프 판정 대상만.
CORE=(siem_logs_init event_collector scoring_engine config_service siem_api aar_report)
SAMPLED=(event_collector scoring_engine config_service siem_api)

log() { echo "[run-soak $(date -u +%H:%M:%S)] $*"; }

cleanup() {
  log "cleanup: stopping sampler/load"
  [ -n "${SAMPLER_PID:-}" ] && kill "$SAMPLER_PID" 2>/dev/null
  [ -n "${LOAD_PID:-}" ] && kill "$LOAD_PID" 2>/dev/null
}
trap cleanup EXIT INT TERM

cd "$ROOT" || exit 3

log "bringing up core stack: ${CORE[*]}"
docker compose up -d --build "${CORE[@]}" 2>&1 | tail -5

log "waiting for core health (event_collector:8010, siem_api:8040, scoring:8020)"
healthy=0
for i in $(seq 1 60); do
  if curl -sf http://localhost:8010/health >/dev/null 2>&1 \
     && curl -sf http://localhost:8040/health >/dev/null 2>&1 \
     && curl -sf http://localhost:8020/health >/dev/null 2>&1; then
    healthy=1; break
  fi
  sleep 3
done
if [ "$healthy" -ne 1 ]; then
  log "ERROR: stack not healthy after 180s"; docker compose ps | tail -10; exit 4
fi
log "stack healthy. siem rules: $(curl -sf http://localhost:8040/stats 2>/dev/null | head -c 200)"

log "starting sampler (interval=${SOAK_SAMPLE_INTERVAL}s) -> $SOAK_SAMPLE_CSV"
bash "$HERE/soak_sample.sh" "${SAMPLED[@]}" > "$RESULTS/sampler.${STAMP}.log" 2>&1 &
SAMPLER_PID=$!

log "starting load: duration=${SOAK_DURATION_SEC}s rate=${SOAK_RATE}/s"
python3 "$HERE/soak_load.py" > "$RESULTS/load.${STAMP}.log" 2>&1 &
LOAD_PID=$!

# 부하가 끝날 때까지 대기(부하 스크립트가 duration 을 관리)
wait "$LOAD_PID"
LOAD_RC=$?
log "load finished rc=$LOAD_RC"

kill "$SAMPLER_PID" 2>/dev/null; SAMPLER_PID=""

log "=== ANALYSIS ==="
python3 "$HERE/soak_analyze.py" "$SOAK_SAMPLE_CSV" | tee "$RESULTS/analysis.${STAMP}.txt"
ANALYZE_RC=${PIPESTATUS[0]}

# === R-1 게이트(audit/102): 소크로 커진 events.db 에서 종료 시점 AAR PDF·reconcile 이 OOM 없이 =====
# 성공하는지 판정한다. 무한 replay(fetchall) 회귀가 재발하면 여기서 event_collector 가 죽는다.
log "=== R-1 gate: 종료 시점 AAR/reconcile (성장한 events.db) ==="
R1_GATE="$RESULTS/soak_r1_gate.${STAMP}.json"
# AAR PDF 는 instructor 인증 필요. 컨테이너는 .env 의 INSTRUCTOR_TOKEN 을 쓰므로 게이트도 동일 값 사용
# (미설정 시 dev 토큰). RBAC_ALLOW_INSECURE_DEV 는 토큰이 '구성돼 있으면' 우회하지 않는다.
if [ -z "${INSTRUCTOR_TOKEN:-}" ] && [ -f "$ROOT/.env" ]; then
  INSTRUCTOR_TOKEN="$(grep -E '^INSTRUCTOR_TOKEN=' "$ROOT/.env" | head -1 | cut -d= -f2-)"
fi
export INSTRUCTOR_TOKEN
SOAK_SCENARIO_ID="${SOAK_SCENARIO_ID:-soak}" python3 - "$R1_GATE" <<'PY' | tee -a "$RESULTS/analysis.${STAMP}.txt"
import json, os, sys, urllib.request
out = sys.argv[1]
scen = os.environ.get("SOAK_SCENARIO_ID", "soak")
tok = os.environ.get("INSTRUCTOR_TOKEN", "dev-instructor-token")
def get(url, headers=None, timeout=60):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read()
res = {"scenario": scen, "checks": {}}
ok = True
# 1) event_collector 헬스(무한 replay 로 죽지 않았는지)
try:
    s, _ = get("http://localhost:8010/health"); res["checks"]["event_collector_health"] = s
    ok = ok and s == 200
except Exception as e:
    res["checks"]["event_collector_health"] = f"ERR {type(e).__name__}"; ok = False
# 2) reconcile(events 크로스체크가 checked=True 로 완료 — OOM 이면 checked=False/에러)
try:
    s, b = get(f"http://localhost:8020/scores/reconcile?scenario_id={scen}", timeout=90)
    cc = json.loads(b).get("events_crosscheck", {})
    res["checks"]["reconcile"] = {"http": s, "checked": cc.get("checked"), "total_events": cc.get("total_events")}
    ok = ok and s == 200 and cc.get("checked") is True
except Exception as e:
    res["checks"]["reconcile"] = f"ERR {type(e).__name__}"; ok = False
# 3) AAR PDF(성장한 DB 에서 생성 — 무한 replay 면 502/OOM)
try:
    s, b = get(f"http://localhost:8090/report/aar/pdf?scenario_id={scen}",
               headers={"Authorization": f"Bearer {tok}"}, timeout=120)
    res["checks"]["aar_pdf"] = {"http": s, "is_pdf": b[:5] == b"%PDF-", "size": len(b)}
    ok = ok and s == 200 and b[:5] == b"%PDF-"
except Exception as e:
    res["checks"]["aar_pdf"] = f"ERR {type(e).__name__}"; ok = False
# 4) event_collector 헬스 재확인(reconcile+AAR 의 무거운 replay 후에도 살아있는지)
try:
    s, _ = get("http://localhost:8010/health"); res["checks"]["event_collector_health_after"] = s
    ok = ok and s == 200
except Exception as e:
    res["checks"]["event_collector_health_after"] = f"ERR {type(e).__name__}"; ok = False
res["verdict"] = "PASS" if ok else "FAIL"
with open(out, "w", encoding="utf-8") as fh:
    json.dump(res, fh, ensure_ascii=False, indent=2)
print("R-1 gate:", json.dumps(res["checks"], ensure_ascii=False), "->", res["verdict"])
sys.exit(0 if ok else 5)
PY
R1_RC=${PIPESTATUS[0]}
log "R-1 gate rc=$R1_RC (결과 $R1_GATE)"

if [ "${SOAK_KEEP_UP:-0}" != "1" ]; then
  log "tearing down core stack"
  docker compose stop "${CORE[@]}" >/dev/null 2>&1
fi

log "DONE. results in $RESULTS (stamp=$STAMP). analyze_rc=$ANALYZE_RC r1_gate_rc=${R1_RC:-NA}"
# RSS 슬로프 분석 또는 R-1 게이트 중 하나라도 실패하면 소크 실패.
if [ "$ANALYZE_RC" -ne 0 ] || [ "${R1_RC:-0}" -ne 0 ]; then exit 1; fi
exit 0
