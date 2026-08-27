#!/usr/bin/env bash
# U-6 소크 메모리 샘플러 — INTERVAL 초마다 대상 컨테이너의 RSS/CPU 와 재시작 횟수를
# CSV 로 append 한다. docker stats 는 컨테이너 cgroup 메모리(=RSS 근사)를 준다.
#
# 사용: SOAK_SAMPLE_CSV=... SOAK_SAMPLE_INTERVAL=60 soak_sample.sh <container...>
set -u

CSV="${SOAK_SAMPLE_CSV:-$(dirname "$0")/results/mem_samples.csv}"
INTERVAL="${SOAK_SAMPLE_INTERVAL:-60}"
mkdir -p "$(dirname "$CSV")"

CONTAINERS=("$@")
if [ "${#CONTAINERS[@]}" -eq 0 ]; then
  echo "usage: soak_sample.sh <container...>" >&2
  exit 2
fi

# mem_bytes 는 "123.4MiB / 512MiB" 형태에서 앞부분을 바이트로 환산.
to_bytes() {
  local v="$1" num unit
  num="${v%[A-Za-z]*}"
  unit="${v//[0-9.]/}"
  case "$unit" in
    B)   awk -v n="$num" 'BEGIN{printf "%d", n}';;
    KiB) awk -v n="$num" 'BEGIN{printf "%d", n*1024}';;
    MiB) awk -v n="$num" 'BEGIN{printf "%d", n*1024*1024}';;
    GiB) awk -v n="$num" 'BEGIN{printf "%d", n*1024*1024*1024}';;
    *)   echo 0;;
  esac
}

if [ ! -f "$CSV" ]; then
  echo "epoch,container,mem_bytes,mem_perc,cpu_perc,restarts" > "$CSV"
fi

echo "[soak-sample] csv=$CSV interval=${INTERVAL}s containers=${CONTAINERS[*]}" >&2

while true; do
  now=$(date +%s)
  # docker stats 한 번에 전 컨테이너 조회(--no-stream)
  stats=$(docker stats --no-stream --format '{{.Name}}|{{.MemUsage}}|{{.MemPerc}}|{{.CPUPerc}}' 2>/dev/null)
  for c in "${CONTAINERS[@]}"; do
    line=$(echo "$stats" | grep -E "^${c}\|" | head -1)
    if [ -z "$line" ]; then
      continue
    fi
    memusage=$(echo "$line" | cut -d'|' -f2)      # "123.4MiB / 512MiB"
    memperc=$(echo "$line" | cut -d'|' -f3 | tr -d '%')
    cpuperc=$(echo "$line" | cut -d'|' -f4 | tr -d '%')
    used=$(echo "$memusage" | awk -F'/' '{gsub(/ /,"",$1); print $1}')
    bytes=$(to_bytes "$used")
    restarts=$(docker inspect -f '{{.RestartCount}}' "$c" 2>/dev/null || echo -1)
    echo "${now},${c},${bytes},${memperc},${cpuperc},${restarts}" >> "$CSV"
  done
  sleep "$INTERVAL"
done
