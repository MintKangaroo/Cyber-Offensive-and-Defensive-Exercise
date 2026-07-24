"""
B0 계약: 서비스 API 명세 (엔드포인트 계약)
=============================================
각 서비스가 제공/소비하는 HTTP·WS 엔드포인트의 단일 참조.
프론트/백엔드/에이전트가 이 상수를 공유해 경로 불일치를 방지한다.
구현이 아니라 '계약'이다(실제 라우팅은 각 서비스가 구현).

이 파일은 B0만 수정한다.
"""

from __future__ import annotations
from pydantic import BaseModel
from typing import Optional


# ---- 서비스 포트(단일 진실원) ----
class Ports:
    GROUND_STATION = 8001
    POWER_PLANT = 8002
    DEFENSE_NETWORK = 8003
    EVENT_COLLECTOR = 8010
    SCORING_ENGINE = 8020
    CONFIG_SERVICE = 8030      # 신규(패치 무중단 토글)
    SIEM_API = 8040            # 신규(SIEM 검색/알림)
    SCENARIO_ENGINE = 8045     # 신규(시나리오 활성화/진행조회)
    INSTRUCTOR_API = 8050      # 신규(교관 콘솔)
    EDR_BACKEND = 8080         # 신규(EDR 텔레메트리/isolate/kill)
    NOC_MONITOR = 8070         # 신규(가용성 모니터링)
    PATCH_CONSOLE = 8060       # 신규(Ansible 패치 콘솔)


# ---- Event Collector (8010) ----
class EventCollectorAPI:
    INGEST = "POST /events"                 # body: Event
    LIST = "GET /events"                    # ?limit&target_asset&team_id
    STREAM_WS = "WS /ws"                    # 실시간 이벤트 브로드캐스트
    REPLAY = "GET /replay/events"           # ?scenario_id&from&to (대시보드 리플레이)


# ---- Scoring Engine (8020) ----
class ScoringAPI:
    INGEST = "POST /score/ingest"           # body: Event
    SCORES = "GET /scores"                  # ?scenario_id
    HISTORY = "GET /scores/history"         # ?scenario_id&team_id
    RECONCILE = "GET /scores/reconcile"     # ?scenario_id (점수↔이벤트 정합성 감사)


# ---- Config Service (8030) — 패치 무중단 토글 ----
class ConfigAPI:
    GET_PATCHES = "GET /config/patches"     # ?asset -> {vuln_id: bool}
    TOGGLE = "POST /instructor/patch/toggle"  # 교관, body: {asset,vuln_id,patched,reason}
    KILLSWITCH = "POST /instructor/killswitch"  # 교관
    KILLSWITCH_RELEASE = "POST /instructor/killswitch/release"


# ---- SIEM API (8040) ----
class SiemAPI:
    SEARCH = "GET /search"                  # SearchQuery 파라미터
    ALERTS = "GET /alerts"                  # ?status&severity
    ALERT_UPDATE = "POST /alerts/{id}"      # 상태 변경(open/ack/closed)
    STATS = "GET /stats"                    # EPS, severity 분포, top signatures
    SOURCE_HEALTH = "GET /sources/health"
    ATTACK_COVERAGE = "GET /detection/attack-coverage"
    LOGS_WS = "WS /ws/logs"
    ALERTS_WS = "WS /ws/alerts"


# ---- Instructor API (8050) ----
class InstructorAPI:
    SCENARIO_START = "POST /instructor/scenario/start"
    SCENARIO_END = "POST /instructor/scenario/end"
    EVENT_INJECT = "POST /instructor/event/inject"
    SCORE_ADJUST = "POST /instructor/score/adjust"   # reason 필수
    AUDIT = "GET /instructor/audit"


# ---- 공통 요청/응답 모델(교관 조작 등 검증 대상) ----
class PatchToggleRequest(BaseModel):
    asset: str
    vuln_id: str
    patched: bool
    reason: str            # audit 필수


class ScoreAdjustRequest(BaseModel):
    team_id: str
    scenario_id: str = "default"
    actor: str             # red|blue
    delta: int
    reason: str            # 필수(없으면 400)


class GradeResult(BaseModel):
    """챌린지 채점기 공통 반환형(11번 채점 계약)."""
    passed: bool
    points: int
    detail: str = ""
