"""
Background Traffic Profile (감사 §3 G-11: 네트워크 계층 배경 트래픽)
====================================================================
탐지 훈련은 "노이즈 속에서 공격을 골라내기"가 전제다. 그런데 기존
`services/siem/detection/noise_generator.py`는 siem_api 프로세스 **내부에서** 합성 로그
문자열을 만들어 탐지엔진에 직접 먹일 뿐, 실제 트윈을 거치지도(=네트워크 계층 부재)
access 로그 파일을 남기지도 않는다(감사 G-11: "생성기는 있으나 기본 비활성, SIEM 이벤트만
합성(네트워크 계층 아님)").

이 모듈은 **실제 트윈의 양성(benign) 엔드포인트**로 흘려보낼 요청 카탈로그와 스케줄을
순수함수로 정의한다. driver(`driver.py`)가 이걸 받아 실 HTTP를 쏘면, 트윈의
`shared/siem_access_log` 미들웨어가 진짜 access 로그를 남기고 → siem_api file_tailer →
`parse_twin_log_line` → DetectionEngine 으로, **공격 트래픽과 완전히 동일한 파이프라인**을
통과한다.

설계 원칙:
  * **양성만** — vuln-map 되지 않은 read/health 경로만 사용한다. 파서의
    `_severity_from_status`는 vuln_id 없는 200 응답을 severity 0(info)으로 본다 →
    깨끗한 노이즈. Blue의 탐지 룰이 과도하게 넓을 때만 알림이 뜨고, 그건 ground truth상
    배경이므로 오탐으로 채점된다(AAR `compute_false_positive_rate`).
  * **ground truth 라벨** — driver가 `X-Background-Traffic` 헤더를 붙이고 미들웨어가
    access 로그에 `is_background=true`를 찍는다. 이게 오탐률의 근거다.
  * **업무시간 가중** — 9~18시에 트래픽을 늘려 현실적인 다이얼 패턴을 흉내낸다
    (noise_generator와 동일 컨벤션).
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class BenignEndpoint:
    """트윈 하나의 양성 엔드포인트. weight가 클수록 자주 선택된다."""
    method: str
    path: str
    weight: float = 1.0
    body: Optional[dict] = None  # POST용(현재 카탈로그는 전부 GET)


# 트윈 컨테이너명 -> 내부 uvicorn 포트(섹터마다 다름; Dockerfile CMD 기준).
# 호스트 미노출이므로 traffic_generator가 트윈망에서 컨테이너명:포트로 직접 도달한다.
TWIN_PORTS: dict[str, int] = {
    "ground_station": 8001,
    "power_plant": 8002,
    "defense_network": 8003,
    "refinery_plant": 8201,
    "smart_factory": 8202,
    "water_utility": 8203,
    "lng_terminal": 8204,
    "railway_signaling": 8205,
    "airport_ot": 8206,
    "datacenter_bms": 8207,
    "hospital_ot": 8208,
    "cloud_native": 8209,
}

# 양성 엔드포인트 카탈로그. 기본은 모든 트윈이 가진 GET /health(모니터링 하트비트,
# vuln-map 안 됨, 킬스위치에도 응답). 일부 트윈은 추가 read-only 텔레메트리를 노출한다
# (반드시 route_vuln_map에 없는 경로만 — 그래야 severity 0 clean noise가 유지된다).
_HEALTH = BenignEndpoint("GET", "/health", weight=3.0)
BENIGN_CATALOG: dict[str, list[BenignEndpoint]] = {
    asset: [_HEALTH] for asset in TWIN_PORTS
}
# power_plant는 vuln-map 되지 않은 양성 read(/api/plc/read)를 추가로 노출한다.
BENIGN_CATALOG["power_plant"] = [_HEALTH, BenignEndpoint("GET", "/api/plc/read", weight=2.0)]

# 훈련장 내부 '정상 사용자/모니터링' 대역(더미). driver가 X-Forwarded-For로 실어 보내면
# 미들웨어가 이걸 src_ip로 기록한다 → 공격자 IP와 구분되는 배경 트래픽 출처.
INTERNAL_USER_BAND: list[str] = [f"10.50.0.{i}" for i in range(10, 40)]

# 배경 트래픽 요청에 붙는 UA(로그에서 사람이 배경임을 눈으로도 식별 가능하게).
BACKGROUND_USER_AGENT = "RangeMonitor/1.0 (background-traffic)"


def business_hours_weight(dt: datetime) -> float:
    """9~18시는 1.0, 그 외 시간은 0.3 — 업무시간 트래픽이 더 많은 현실적 패턴."""
    return 1.0 if 9 <= dt.hour < 18 else 0.3


@dataclass
class TrafficProfile:
    """배경 트래픽 생성 파라미터. base_eps=초당 평균 요청 수(업무시간 가중 전)."""
    base_eps: float = 1.0
    assets: list[str] = field(default_factory=lambda: list(TWIN_PORTS.keys()))
    catalog: dict[str, list[BenignEndpoint]] = field(default_factory=lambda: BENIGN_CATALOG)

    def enabled_assets(self) -> list[str]:
        """카탈로그에 양성 엔드포인트가 있고 포트를 아는 트윈만."""
        return [a for a in self.assets if self.catalog.get(a) and a in TWIN_PORTS]

    def effective_eps(self, now: datetime) -> float:
        """업무시간 가중을 반영한 실효 eps(최소 0.1 보장)."""
        return max(0.1, self.base_eps * business_hours_weight(now))

    def interval_seconds(self, now: datetime) -> float:
        return 1.0 / self.effective_eps(now)


@dataclass(frozen=True)
class PlannedRequest:
    asset: str
    port: int
    method: str
    path: str
    src_ip: str
    body: Optional[dict] = None

    @property
    def url(self) -> str:
        return f"http://{self.asset}:{self.port}{self.path}"


def _weighted_choice(items: list[BenignEndpoint], rng: random.Random) -> BenignEndpoint:
    total = sum(max(0.0, e.weight) for e in items) or 1.0
    r = rng.random() * total
    upto = 0.0
    for e in items:
        upto += max(0.0, e.weight)
        if r <= upto:
            return e
    return items[-1]


def plan_request(profile: TrafficProfile, rng: Optional[random.Random] = None) -> Optional[PlannedRequest]:
    """다음에 쏠 양성 요청 하나를 순수하게 선택한다(부수효과 없음, 테스트 용이).
    사용 가능한 트윈이 없으면 None."""
    rng = rng or random
    assets = profile.enabled_assets()
    if not assets:
        return None
    asset = rng.choice(assets)
    endpoint = _weighted_choice(profile.catalog[asset], rng)
    return PlannedRequest(
        asset=asset,
        port=TWIN_PORTS[asset],
        method=endpoint.method,
        path=endpoint.path,
        src_ip=rng.choice(INTERNAL_USER_BAND),
        body=endpoint.body,
    )
