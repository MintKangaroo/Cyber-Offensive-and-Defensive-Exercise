"""
Patch Console Whitelist
=========================
vuln_id -> playbook 경로의 **명시적** 매핑. f-string으로 경로를 조합하지 않는다.
(vuln_id에 '../../etc/passwd' 류 입력이 들어오면 경로탈출이 되는 걸 원천 차단)

새 취약점을 추가할 때는 반드시 이 딕셔너리에 한 줄을 추가하는 방식으로만 확장한다.
"""
from pathlib import Path

PLAYBOOK_DIR = Path(__file__).parent / "playbooks"

# vuln_id -> (playbook 파일명, 대상 asset, Ansible group)
WHITELIST: dict[str, dict[str, str]] = {
    "GS-001": {"playbook": "patch_GS-001.yml", "asset": "ground_station", "group": "ground_station_twin"},
    "GS-002": {"playbook": "patch_GS-002.yml", "asset": "ground_station", "group": "ground_station_twin"},
    "GS-003": {"playbook": "patch_GS-003.yml", "asset": "ground_station", "group": "ground_station_twin"},
    "GS-004": {"playbook": "patch_GS-004.yml", "asset": "ground_station", "group": "ground_station_twin"},
    "GS-005": {"playbook": "patch_GS-005.yml", "asset": "ground_station", "group": "ground_station_twin"},
    "PP-001": {"playbook": "patch_PP-001.yml", "asset": "power_plant", "group": "power_plant_twin"},
    "PP-002": {"playbook": "patch_PP-002.yml", "asset": "power_plant", "group": "power_plant_twin"},
    "PP-003": {"playbook": "patch_PP-003.yml", "asset": "power_plant", "group": "power_plant_twin"},
    "PP-004": {"playbook": "patch_PP-004.yml", "asset": "power_plant", "group": "power_plant_twin"},
    "PP-005": {"playbook": "patch_PP-005.yml", "asset": "power_plant", "group": "power_plant_twin"},
    "DN-001": {"playbook": "patch_DN-001.yml", "asset": "defense_network", "group": "defense_network_twin"},
    "DN-002": {"playbook": "patch_DN-002.yml", "asset": "defense_network", "group": "defense_network_twin"},
    "DN-003": {"playbook": "patch_DN-003.yml", "asset": "defense_network", "group": "defense_network_twin"},
    "DN-004": {"playbook": "patch_DN-004.yml", "asset": "defense_network", "group": "defense_network_twin"},
}


def resolve_playbook_path(vuln_id: str) -> Path | None:
    """화이트리스트에 있는 vuln_id만 실제 파일 경로를 반환. 없으면 None(400 처리는 API 계층)."""
    entry = WHITELIST.get(vuln_id)
    if entry is None:
        return None
    path = (PLAYBOOK_DIR / entry["playbook"]).resolve()
    # 이중 검증: resolve() 후에도 PLAYBOOK_DIR 하위인지 확인(방어적 코딩)
    if not str(path).startswith(str(PLAYBOOK_DIR.resolve())):
        return None
    if not path.exists():
        return None
    return path


def is_whitelisted(vuln_id: str) -> bool:
    return vuln_id in WHITELIST


def list_available() -> list[dict[str, str]]:
    return [{"vuln_id": k, **v} for k, v in WHITELIST.items()]
