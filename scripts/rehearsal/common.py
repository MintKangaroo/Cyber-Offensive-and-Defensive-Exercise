"""리허설 공통: 환경 로드·HTTP 헬퍼·서비스 토큰·PASS/FAIL 리포터."""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import requests

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:  # dotenv 없어도 환경변수만으로 동작
    pass

# --- 서비스 엔드포인트(호스트 기준, 서브셋 기동 시 발행 포트) ---
EVENT_COLLECTOR = os.environ.get("EVENT_COLLECTOR_HOST_URL", "http://localhost:8010").rstrip("/")
SCORING_ENGINE = os.environ.get("SCORING_ENGINE_HOST_URL", "http://localhost:8020").rstrip("/")
SIEM_API = os.environ.get("SIEM_API_HOST_URL", "http://localhost:8040").rstrip("/")
AAR_REPORT = os.environ.get("AAR_REPORT_HOST_URL", "http://localhost:8090").rstrip("/")
AD_API = os.environ.get("ATTACK_DEFENSE_API_URL", "http://localhost:8100").rstrip("/")
AUTH_API = os.environ.get("AUTH_API_URL", "http://localhost:8051").rstrip("/")

SERVICE_TOKEN = os.environ.get("SERVICE_TOKEN", "")
INSTRUCTOR_TOKEN = os.environ.get("INSTRUCTOR_TOKEN", "dev-instructor-token")


def service_headers() -> dict[str, str]:
    """S2S 인제스트용 헤더(감사 3.1). SERVICE_TOKEN 설정 시 Bearer, 아니면 빈 헤더(dev)."""
    return {"Authorization": f"Bearer {SERVICE_TOKEN}"} if SERVICE_TOKEN else {}


def instructor_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {INSTRUCTOR_TOKEN}"}


def wait_health(url: str, timeout: int = 60, name: str = "") -> bool:
    """/health 가 200 될 때까지 대기."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if requests.get(url, timeout=3).status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(2)
    return False


@dataclass
class Reporter:
    """PASS/FAIL 집계 + 근거 기록(audit/102 로 덤프)."""
    name: str
    checks: list[dict[str, Any]] = field(default_factory=list)

    def check(self, ok: bool, label: str, evidence: str = "") -> bool:
        mark = "✅ PASS" if ok else "❌ FAIL"
        print(f"  {mark}  {label}" + (f"  — {evidence}" if evidence else ""))
        self.checks.append({"ok": bool(ok), "label": label, "evidence": evidence})
        return ok

    def note(self, label: str, evidence: str = "") -> None:
        print(f"  ·      {label}" + (f"  — {evidence}" if evidence else ""))
        self.checks.append({"ok": None, "label": label, "evidence": evidence})

    @property
    def passed(self) -> int:
        return sum(1 for c in self.checks if c["ok"] is True)

    @property
    def failed(self) -> int:
        return sum(1 for c in self.checks if c["ok"] is False)

    @property
    def ok(self) -> bool:
        return self.failed == 0

    def summary_line(self) -> str:
        return f"[{self.name}] PASS={self.passed} FAIL={self.failed}"
