"""
Recovery Watcher (04번 문서 2절 구현)
======================================
asset_recovered(+50) 발행 조건:
  (1) 해당 자산이 과거에 asset_compromised 이력이 있고
  (2) 관련 취약점이 Config Service에서 patched로 확인되고
  (3) Health Poller가 '3회 연속 정상'을 감지
세 조건을 AND로 결합해야 최종 발행. NOC의 Health Poller는 (3)만 신호로 주고,
이 워처가 (1)(2)와 결합해 최종 판정한다(NOC API의 _on_recovery는 후보 신호일 뿐).
"""
from __future__ import annotations
import asyncio
import time
from pathlib import Path
from dataclasses import dataclass, field

import httpx

import sys
sys.path.append(str(Path(__file__).parent.parent.parent))
from shared.event_schema import Event, EventType  # noqa: E402
from shared.service_auth import service_headers  # noqa: E402

CONFIG_SERVICE_URL = "http://config_service:8030"
EVENT_COLLECTOR_URL = "http://event_collector:8010"


@dataclass
class CompromiseRecord:
    """asset_compromised 이후 어떤 vuln_id가 원인이었는지 추적(복구 판정에 필요)."""
    asset: str
    vuln_id: str
    team_id: str
    scenario_id: str = "default"   # 복구 점수를 침해와 같은 시나리오 버킷에 귀속시키기 위해 보존
    compromised_at: float = field(default_factory=time.time)
    recovered: bool = False


class RecoveryWatcher:
    def __init__(self, health_poller):
        self.health_poller = health_poller
        self.compromises: list[CompromiseRecord] = []
        health_poller.on_recovery_condition_met(self._on_health_recovery_candidate)

    def record_compromise(self, asset: str, vuln_id: str, team_id: str, scenario_id: str = "default") -> None:
        """asset_compromised 이벤트 수신 시 Event Collector 구독 측에서 호출."""
        self.compromises.append(
            CompromiseRecord(asset=asset, vuln_id=vuln_id, team_id=team_id, scenario_id=scenario_id)
        )

    async def _on_health_recovery_candidate(self, asset: str) -> None:
        """Health Poller가 '3회 연속 정상'을 알리면, 이 자산의 미해결 compromise 기록들에 대해
        patched 여부를 확인하고 조건 충족 시 asset_recovered를 발행한다."""
        pending = [c for c in self.compromises if c.asset == asset and not c.recovered]
        if not pending:
            return   # 침해 이력 없이 재기동한 경우는 복구 점수 대상 아님(04번 2절 원칙)

        for record in pending:
            patched = await self._check_patched(record.asset, record.vuln_id)
            if patched:
                record.recovered = True
                await self._emit_asset_recovered(record)

    async def _check_patched(self, asset: str, vuln_id: str) -> bool:
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                r = await client.get(f"{CONFIG_SERVICE_URL}/config/patches", params={"asset": asset})
                data = r.json()
                return bool(data.get(vuln_id, False))
        except httpx.HTTPError:
            return False

    async def _emit_asset_recovered(self, record: CompromiseRecord) -> None:
        event = {
            "event_id": Event.make_id(record.team_id, record.asset, "recovered", str(time.time())),
            "event_type": EventType.asset_recovered.value,
            "actor": "blue",
            "team_id": record.team_id,
            "scenario_id": record.scenario_id,   # 침해와 동일 시나리오에 복구 점수 귀속
            "target_asset": record.asset,
            "vuln_id": record.vuln_id,
            "metadata": {
                "compromised_at": record.compromised_at,
                "recovered_at": time.time(),
                "dwell_sec": round(time.time() - record.compromised_at, 1),
            },
        }
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                await client.post(f"{EVENT_COLLECTOR_URL}/events", json=event, headers=service_headers())
        except httpx.HTTPError:
            pass  # Event Collector 다운 시 유실 방지를 위해 재시도 큐 도입 권장(운영 확장 시)
