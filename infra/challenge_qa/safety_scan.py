#!/usr/bin/env python3
"""
C-QA Step 6: Safety Scan (25번 문서 1절)
============================================
(a) infra/ci/secret_scan.py 재사용
(b) safety.profile == "hardened"인데 deploy/docker-compose.yaml에
    cap_drop/read_only/mem_limit이 없으면 경고+실패
"""
import argparse
import subprocess
import sys
from pathlib import Path

import yaml

RCE_CATEGORIES = {"ai", "reversing"}  # 08번 문서: RCE류는 hardened 강제 대상


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--challenge-dir", required=True)
    ap.add_argument("--secret-scan-script",
                    default=str(Path(__file__).parent.parent / "ci" / "secret_scan.py"))
    args = ap.parse_args()

    challenge_dir = Path(args.challenge_dir)

    # (a) 시크릿 스캔
    rc = subprocess.run([sys.executable, args.secret_scan_script, "--path", str(challenge_dir)]).returncode
    if rc != 0:
        print("❌ safety_scan: 시크릿 스캔 실패")
        return 1

    # (b) hardened 프로파일 검증
    yaml_path = challenge_dir / "challenge.yaml"
    with open(yaml_path) as f:
        data = yaml.safe_load(f)
    challenge = data.get("challenge", {})
    safety = challenge.get("safety", {})
    profile = safety.get("profile", "standard")
    category = challenge.get("category", "")

    if category in RCE_CATEGORIES and profile != "hardened":
        print(f"⚠️  safety_scan: category='{category}'는 RCE 가능성이 높아 hardened 프로파일을 "
             f"권장하나 현재 '{profile}'로 설정됨")
        # 경고만 하고 실패 처리는 안 함(문제 성격에 따라 판단 필요 -> 사람이 검토)

    if profile == "hardened":
        compose_path = challenge_dir / "deploy" / "docker-compose.yaml"
        if not compose_path.exists():
            print("❌ safety_scan: hardened인데 docker-compose.yaml 없음")
            return 1
        text = compose_path.read_text()
        missing = [k for k in ["cap_drop", "read_only", "mem_limit"] if k not in text]
        if missing:
            print(f"❌ safety_scan: hardened 프로파일인데 다음 하드닝 설정 누락: {missing}")
            return 1

    print(f"✅ safety_scan: 통과 (profile={profile}, category={category})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
