#!/usr/bin/env python3
"""
C-QA Step 1: Schema Validation (25번 문서 1절)
==================================================
challenges/<category>/<id>/challenge.yaml이 표준 스키마를 준수하는지 검증.
"""
import argparse
import sys
from pathlib import Path

import yaml

REQUIRED_TOP = ["id", "title", "category", "difficulty", "points"]
VALID_DIFFICULTY = {"easy", "medium", "hard", "insane"}
VALID_CATEGORY = {"web", "forensics", "detection", "ai", "reversing", "network"}


def find_challenge_dir(challenge_id: str, challenges_root: Path) -> Path | None:
    for path in challenges_root.rglob("challenge.yaml"):
        with open(path) as f:
            data = yaml.safe_load(f)
        if data.get("challenge", {}).get("id") == challenge_id:
            return path.parent
    return None


def validate(challenge_dir: Path) -> list[str]:
    errors = []
    yaml_path = challenge_dir / "challenge.yaml"
    if not yaml_path.exists():
        return [f"challenge.yaml not found in {challenge_dir}"]

    with open(yaml_path) as f:
        data = yaml.safe_load(f)
    challenge = data.get("challenge", {})

    for field in REQUIRED_TOP:
        if field not in challenge:
            errors.append(f"missing required field: {field}")

    if challenge.get("difficulty") not in VALID_DIFFICULTY:
        errors.append(f"invalid difficulty: {challenge.get('difficulty')}")
    if challenge.get("category") not in VALID_CATEGORY:
        errors.append(f"invalid category: {challenge.get('category')}")

    import re
    if "id" in challenge and not re.match(r"^[A-Z]{2,4}-\d{3}$", challenge["id"]):
        errors.append(f"id format invalid (expected e.g. 'WEB-002'): {challenge['id']}")

    points = challenge.get("points", {})
    if not isinstance(points, dict) or "red" not in points or "blue" not in points:
        errors.append("points must have 'red' and 'blue' keys")

    # 필수 서브디렉토리 존재 확인(11번 문서 1절 표준 구조)
    for required_dir in ["deploy", "solution", "grader"]:
        if not (challenge_dir / required_dir).exists():
            errors.append(f"missing required directory: {required_dir}/")

    return errors


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--challenge", required=True, help="challenge id, e.g. WEB-002")
    ap.add_argument("--challenges-root", default="challenges")
    args = ap.parse_args()

    challenge_dir = find_challenge_dir(args.challenge, Path(args.challenges_root))
    if challenge_dir is None:
        print(f"❌ challenge '{args.challenge}' not found under {args.challenges_root}")
        return 1

    errors = validate(challenge_dir)
    if errors:
        print(f"❌ schema_validate: {len(errors)} error(s) in {challenge_dir}")
        for e in errors:
            print(f"   - {e}")
        return 1

    print(f"✅ schema_validate: {args.challenge} OK ({challenge_dir})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
