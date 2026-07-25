#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# 매치별 트윈 셋 배포 (P2 완전 물리 격리) — 교관이 호스트에서 실행(range_control 서비스는
# docker 소켓 미노출 원칙, #11). 별도 compose 프로젝트로 트윈 인스턴스를 띄우고, 코어를 이
# 매치의 internal 네트워크에 connect해 트윈→코어만 허용한다.
#
# 사용: scripts/deploy_match.sh <match_id> <port_base>
#   예: scripts/deploy_match.sh match_A 8300   → ref 8301 / fac 8302 / wtr 8303, scenario=match_A
# ---------------------------------------------------------------------------
set -euo pipefail
MATCH="$(echo "${1:?match_id 필요 (예: match_a)}" | tr '[:upper:]' '[:lower:]')"   # docker 프로젝트명은 소문자
BASE="${2:?port_base 필요 (예: 8300)}"
PROJECT="${MATCH}"
CORE_NET="cyber-range-platform_range_control"   # 코어가 붙어있는 네트워크(참고)
CORE_SVCS=(event_collector config_service edr_backend siem_api)
COMPOSE="$(dirname "$0")/../infra/match/docker-compose.match.yml"

echo "▶ 매치 트윈 셋 배포: $MATCH (scenario=$MATCH, ports $((BASE+1))~$((BASE+11)) = 11섹터 전체)"
MATCH_SCENARIO_ID="$MATCH" \
  REF_PORT=$((BASE+1)) FAC_PORT=$((BASE+2)) WTR_PORT=$((BASE+3)) LNG_PORT=$((BASE+4)) \
  RWY_PORT=$((BASE+5)) AIR_PORT=$((BASE+6)) DCX_PORT=$((BASE+7)) HSP_PORT=$((BASE+8)) \
  GS_PORT=$((BASE+9)) PP_PORT=$((BASE+10)) DN_PORT=$((BASE+11)) \
  docker compose -p "$PROJECT" -f "$COMPOSE" up -d --build

TWINNET="${PROJECT}_twinnet"
echo "▶ 코어를 매치 internal 네트워크($TWINNET)에 connect(트윈→코어 허용)"
for svc in "${CORE_SVCS[@]}"; do
  docker network connect "$TWINNET" "$svc" 2>/dev/null && echo "  connected $svc" || echo "  (이미 연결/없음) $svc"
done

# range_control에 매치 등록(포트 기록)
if [ -n "${INSTRUCTOR_TOKEN:-}" ]; then
  curl -s -X POST "http://localhost:8055/matches" \
    -H "Authorization: Bearer $INSTRUCTOR_TOKEN" -H 'Content-Type: application/json' \
    -d "{\"range_id\":\"range_1\",\"match_id\":\"$MATCH\",\"twin_set\":[\"refinery_plant\",\"smart_factory\",\"water_utility\",\"lng_terminal\",\"railway_signaling\",\"airport_ot\",\"datacenter_bms\",\"hospital_ot\",\"ground_station\",\"power_plant\",\"defense_network\"],\"scenario_id\":\"$MATCH\"}" >/dev/null \
    && echo "▶ range_control에 매치 등록됨(11섹터)" || echo "▶ (range_control 등록 skip)"
fi
echo "✅ $MATCH 배포 완료 — 11섹터 트윈: http://<HOST>:$((BASE+1))~$((BASE+11))"
