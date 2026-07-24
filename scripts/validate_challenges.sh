#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Docker 불필요 챌린지 검증 (CI용)
# - 전체 챌린지: schema_validate (스키마/필수필드/카테고리)
# - 아티팩트형(deploy/generate_artifact.py + solution/exploit.py:solve): artifact_solve
#   (생성 → 시그니처 분기 solve → grade_red PASS + 빈제출 거부)
# - 탐지형(deploy/generate_datasets.py + grader/blue_grader.py): detection_solve
#   (데이터셋 생성 → 진짜 SIEM DetectionEngine 채점 + no-op 규칙 거부)
# 서비스형(docker 배포 필요)은 스키마만 검사(실배포 검증은 C-QA docker 잡 또는 로컬에서).
# 하나라도 실패하면 비-0 종료.
# ---------------------------------------------------------------------------
set -u
cd "$(dirname "$0")/.."
ROOT="challenges"
QA="infra/challenge_qa"
fail=0; n=0; art=0; det=0; svc=0

for d in "$ROOT"/*/*/; do
  id=$(basename "$d")
  n=$((n + 1))
  if ! python3 "$QA/schema_validate.py" --challenge "$id" >/dev/null 2>&1; then
    echo "❌ SCHEMA   $id"; fail=1; continue
  fi
  if [ -f "$d/deploy/generate_artifact.py" ] && grep -q "def solve" "$d/solution/exploit.py" 2>/dev/null; then
    if python3 "$QA/artifact_solve.py" --challenge-dir "$d" >/dev/null 2>&1; then art=$((art + 1))
    else echo "❌ ARTIFACT $id"; fail=1; fi
  elif [ -f "$d/deploy/generate_datasets.py" ] && [ -f "$d/grader/blue_grader.py" ]; then
    if python3 "$QA/detection_solve.py" --challenge-dir "$d" >/dev/null 2>&1; then det=$((det + 1))
    else echo "❌ DETECT   $id"; fail=1; fi
  else
    svc=$((svc + 1))   # 서비스형/특수: 스키마만
  fi
done

echo "=================================================================="
echo " 검증한 챌린지: $n  (아티팩트 $art / 탐지 $det / 서비스·스키마만 $svc)"
if [ "$fail" -eq 0 ]; then echo " ✅ 전체 통과"; else echo " ❌ 실패 있음"; fi
echo "=================================================================="
exit $fail
