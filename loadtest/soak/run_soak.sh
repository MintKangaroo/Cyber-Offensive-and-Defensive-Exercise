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

CORE=(siem_logs_init event_collector scoring_engine config_service siem_api)
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

if [ "${SOAK_KEEP_UP:-0}" != "1" ]; then
  log "tearing down core stack"
  docker compose stop "${CORE[@]}" >/dev/null 2>&1
fi

log "DONE. results in $RESULTS (stamp=$STAMP). analyze_rc=$ANALYZE_RC"
exit "$ANALYZE_RC"
