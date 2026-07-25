#!/usr/bin/env bash
# 매치 트윈 셋 정리 — 코어를 매치 네트워크에서 disconnect 후 프로젝트 down.
# 사용: scripts/teardown_match.sh <match_id>
set -euo pipefail
MATCH="$(echo "${1:?match_id 필요}" | tr "[:upper:]" "[:lower:]")"
PROJECT="${MATCH}"
TWINNET="${PROJECT}_twinnet"
CORE_SVCS=(event_collector config_service edr_backend siem_api)
COMPOSE="$(dirname "$0")/../infra/match/docker-compose.match.yml"

echo "▶ 코어를 $TWINNET 에서 disconnect"
for svc in "${CORE_SVCS[@]}"; do
  docker network disconnect "$TWINNET" "$svc" 2>/dev/null && echo "  disconnected $svc" || true
done
echo "▶ 매치 프로젝트 down: $MATCH"
docker compose -p "$PROJECT" -f "$COMPOSE" down 2>/dev/null || true
echo "✅ $MATCH 정리 완료"
