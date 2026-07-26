#!/usr/bin/env bash
# .env의 빈 토큰/시크릿을 안전한 랜덤값으로 채운다. 이미 값이 있으면 건드리지 않는다.
# 사용: cp .env.example .env && ./scripts/gen_secrets.sh
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo ".env 없음 — 먼저 'cp .env.example .env'"; exit 1; }
gen() { openssl rand -hex 24 2>/dev/null || head -c 24 /dev/urandom | xxd -p | tr -d '\n'; }
fill() {  # $1=키
  local key="$1" val
  if grep -qE "^${key}=$" .env; then
    val="${2:-$(gen)}"
    # 인플레이스 치환(빈 값만)
    sed -i "s|^${key}=$|${key}=${val}|" .env
    echo "  ${key} 생성"
  else
    echo "  ${key} 유지(이미 값 있음 또는 키 없음)"
  fi
}
echo "▶ .env 시크릿 채우는 중…"
fill INSTRUCTOR_TOKEN
fill RED_TOKEN "red-$(gen)"
fill BLUE_TOKEN "blue-$(gen)"
fill OBSERVER_TOKEN "obs-$(gen)"
fill AUTH_JWT_SECRET
fill CHALLENGE_SECRET
echo "✅ 완료 — .env 를 안전하게 보관하세요(커밋 금지)."
