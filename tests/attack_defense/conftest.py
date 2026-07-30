from __future__ import annotations

from pathlib import Path

import pytest

from services.attack_defense.api import build_components
from services.attack_defense.config import AttackDefenseSettings
from services.attack_defense.game_engine import GameEngine

from .fakes import FakeChecker, FakeInspector, FakeRuntime


@pytest.fixture
def ad(tmp_path: Path):
    settings = AttackDefenseSettings(
        database_path=tmp_path / "attack_defense.db",
        round_duration_seconds=5,
        check_interval_seconds=60,
        auto_engine=False,
        allow_insecure_dev_auth=True,
        allowed_registry="registry.local:5000",
    )
    components = build_components(
        settings, runtime=FakeRuntime(), inspector=FakeInspector()
    )
    checker = FakeChecker()
    components.checker = checker
    components.patches.checker = checker
    components.engine = GameEngine(
        components.db, components.repo, components.flags, components.scoring,
        checker, components.runtime, components.evidence, settings,
        owner_id="test-engine",
    )
    return components


def bootstrap(
    ad, match_id: str = "match-1", teams: int = 3, services: int = 2,
    mode: str = "attack_defense",
):
    ad.repo.create_match("Test Match", 5, 3, {}, match_id, mode)
    for index in range(1, teams + 1):
        ad.repo.add_team(match_id, f"team-{index:02}", f"Team {index}", f"team-{index}")
    specs = [
        ("vulnerable-notes", "Vulnerable Notes", "vulnerable_notes"),
        ("file-vault", "File Vault", "file_vault"),
    ]
    for slug, name, checker in specs[:services]:
        ad.repo.add_service(
            match_id, slug, name, f"registry.local/base/{slug}:v1", 9000,
            checker,
            {
                "endpoint_template": "http://{team_slug}-{service_slug}:9000",
                "management_endpoint_template": "http://{team_slug}-{service_slug}:9001",
            },
            service_id=f"service-{slug}",
        )
    ad.repo.ensure_instances(match_id)
    return match_id
