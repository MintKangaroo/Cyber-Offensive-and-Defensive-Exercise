#!/usr/bin/env python3
"""
C-QA Step 2: Deploy Up (25번 문서 1절)
==========================================
challenge의 deploy/docker-compose.yaml을 기동하고 /health로 준비 확인(최대 30초 재시도).
"""
import argparse
import subprocess
import sys
import time
from pathlib import Path

import requests


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--challenge-dir", required=True)
    ap.add_argument("--health-url", default="http://localhost:8100/health")
    ap.add_argument("--timeout-sec", type=int, default=30)
    args = ap.parse_args()

    deploy_dir = Path(args.challenge_dir) / "deploy"
    if not (deploy_dir / "docker-compose.yaml").exists():
        print(f"❌ deploy_up: docker-compose.yaml 없음 ({deploy_dir})")
        return 1

    rc = subprocess.run(["docker", "compose", "up", "-d", "--build"], cwd=deploy_dir).returncode
    if rc != 0:
        print("❌ deploy_up: docker compose up 실패")
        return 1

    deadline = time.time() + args.timeout_sec
    while time.time() < deadline:
        try:
            r = requests.get(args.health_url, timeout=2)
            if r.ok:
                print(f"✅ deploy_up: 기동 확인 완료 ({args.health_url})")
                return 0
        except requests.exceptions.RequestException:
            pass
        time.sleep(2)

    print(f"❌ deploy_up: {args.timeout_sec}초 내 health check 실패")
    return 1


if __name__ == "__main__":
    sys.exit(main())
