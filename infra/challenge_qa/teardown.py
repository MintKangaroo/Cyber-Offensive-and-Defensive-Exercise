#!/usr/bin/env python3
"""
C-QA Step 8: Teardown (25번 문서 1절)
=========================================
docker compose down -v 후 잔여 컨테이너 없는지 확인.
"""
import argparse
import subprocess
import sys
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--challenge-dir", required=True)
    args = ap.parse_args()

    deploy_dir = Path(args.challenge_dir) / "deploy"
    rc = subprocess.run(["docker", "compose", "down", "-v"], cwd=deploy_dir).returncode
    if rc != 0:
        print("❌ teardown: docker compose down 실패")
        return 1

    # 잔여 컨테이너 확인(프로젝트명 기준 필터)
    project_name = deploy_dir.resolve().name
    result = subprocess.run(
        ["docker", "ps", "-a", "--filter", f"label=com.docker.compose.project={project_name}", "-q"],
        capture_output=True, text=True,
    )
    leftover = [c for c in result.stdout.strip().splitlines() if c]
    if leftover:
        print(f"❌ teardown: 잔여 컨테이너 {len(leftover)}개 발견")
        return 1

    print("✅ teardown: 정리 완료, 잔여 컨테이너 없음")
    return 0


if __name__ == "__main__":
    sys.exit(main())
