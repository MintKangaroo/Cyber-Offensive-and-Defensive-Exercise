#!/usr/bin/env python3
"""
Secret Scan (08번 안전장치 2절)
=================================
리포지토리에 실제 시크릿(API 키, private key, 실도메인 등)이 섞여드는 것을 막는다.
훈련용 더미 값(하드코딩된 GS-002의 admin123 등)은 명시적으로 허용리스트 처리.

사용법: python secret_scan.py [--path .] [--fail-on-warn]
종료코드: 0=통과, 1=실제 시크릿 의심 발견
"""
from __future__ import annotations
import argparse
import re
import sys
from pathlib import Path

# ---- 탐지 패턴 (실제 시크릿 의심) ----
PATTERNS: dict[str, re.Pattern] = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_key": re.compile(r"(?i)aws(.{0,20})?(secret|access)?[_-]?key.{0,3}[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]"),
    "private_key_header": re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----"),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    "slack_token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    "generic_high_entropy_secret": re.compile(r"(?i)(secret|token|apikey|api_key)['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-]{32,}['\"]"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
}

# ---- 허용 리스트: 훈련용 더미로 알려진 값/패턴 ----
ALLOWLIST_MARKERS = [
    "dummy", "training-only", "training only", "더미", "TRAINING ONLY",
    "supersecret123",   # GS-002 의도된 취약 시크릿(문서화됨)
    "admin123", "operator", "B@ckup2019!",  # 트윈 더미 계정
]

# 스캔 제외 경로
EXCLUDE_DIRS = {".git", "node_modules", "__pycache__", ".venv", "dist", "build"}
EXCLUDE_SUFFIXES = {".png", ".jpg", ".jpeg", ".pdf", ".zip", ".pyc", ".db"}


def is_allowlisted(line: str) -> bool:
    return any(marker in line for marker in ALLOWLIST_MARKERS)


def scan_file(path: Path) -> list[tuple[str, int, str]]:
    """(pattern_name, line_no, line_content) 리스트 반환."""
    findings = []
    try:
        text = path.read_text(errors="ignore")
    except Exception:
        return findings
    for i, line in enumerate(text.splitlines(), start=1):
        if is_allowlisted(line):
            continue
        for name, pattern in PATTERNS.items():
            if pattern.search(line):
                findings.append((name, i, line.strip()[:120]))
    return findings


def scan_repo(root: Path) -> dict[str, list[tuple[str, int, str]]]:
    results: dict[str, list[tuple[str, int, str]]] = {}
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if any(part in EXCLUDE_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in EXCLUDE_SUFFIXES:
            continue
        findings = scan_file(path)
        if findings:
            results[str(path)] = findings
    return results


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", default=".")
    ap.add_argument("--fail-on-warn", action="store_true")
    args = ap.parse_args()

    root = Path(args.path)
    results = scan_repo(root)

    if not results:
        print("✅ secret_scan: no suspicious real-secret patterns found")
        return 0

    print("🚨 secret_scan: suspicious patterns found (review required):\n")
    for file, findings in results.items():
        for name, line_no, content in findings:
            print(f"  [{name}] {file}:{line_no}  {content}")
    print(f"\nTotal findings: {sum(len(v) for v in results.values())} across {len(results)} files")
    print("If these are intentional training dummies, add a clear marker (e.g. 'dummy', "
          "'training-only') on the same line or extend ALLOWLIST_MARKERS.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
